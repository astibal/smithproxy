cmake_minimum_required(VERSION 2.8)

SET(SOCLE_DIR "../socle")
SET(SOCLE_COMMON_DIR "../socle/common")

project(smithproxy CXX)
include_directories ("${SOCLE_DIR}")
include_directories ("${SOCLE_COMMON_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}")

add_subdirectory(${SOCLE_DIR} socle_lib)
add_subdirectory(${SOCLE_COMMON_DIR} socle_common_lib)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g  -Wall -std=c++11")
endif()

add_executable(smithproxy smithproxy.cpp mitmhost.cpp mitmproxy.cpp cfgapi.cpp cidr.cpp policy.cpp daemon.cpp sockshostcx.cpp socksproxy.cpp cmdserver.cpp cfgapi_auth.cpp dns.cpp inspectors.cpp)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")

find_package (LibConfig REQUIRED)
if (LIBCONFIGPP_FOUND)
  include_directories(${LIBCONFIGPP_INCLUDE_DIRS})
  target_link_libraries (smithproxy ${LIBCONFIGPP_LIBRARIES})
endif (LIBCONFIGPP_FOUND)

find_package (LibCli REQUIRED)
if (LIBCLI_FOUND)
  include_directories(${LIBCLI_INCLUDE_DIR})
  target_link_libraries (smithproxy ${LIBCLI_LIBRARY})
endif (LIBCLI_FOUND)


target_link_libraries(smithproxy socle_lib pthread ssl crypto rt)



# taken from http://public.kitware.com/Bug/view.php?id=12646
function(install_if_not_exists src dest)
  if(NOT IS_ABSOLUTE "${src}")
    set(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
  endif()
  get_filename_component(src_name "${src}" NAME)
  if (NOT IS_ABSOLUTE "${dest}")
    set(dest "${CMAKE_INSTALL_PREFIX}/${dest}")
  endif()
  install(CODE "
    if(NOT EXISTS \"\$ENV{DESTDIR}${dest}/${src_name}\")
      #file(INSTALL \"${src}\" DESTINATION \"${dest}\")
      message(STATUS \"Installing: \$ENV{DESTDIR}${dest}/${src_name}\")
      execute_process(COMMAND \${CMAKE_COMMAND} -E copy \"${src}\"
                      \"\$ENV{DESTDIR}${dest}/${src_name}\"
                      RESULT_VARIABLE copy_result
                      ERROR_VARIABLE error_output)
      if(copy_result)
        message(FATAL_ERROR \${error_output})
      endif()
    else()
      message(STATUS \"Skipping  : \$ENV{DESTDIR}${dest}/${src_name}\")
    endif()
  ")
endfunction(install_if_not_exists)


macro(InstallSymlink _filepath _sympath)
    get_filename_component(_symname ${_sympath} NAME)
    get_filename_component(_installdir ${_sympath} PATH)

    if (BINARY_PACKAGING_MODE)
        execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                        ${_filepath}
                        ${CMAKE_CURRENT_BINARY_DIR}/${_symname})
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${_symname}
                DESTINATION ${_installdir})
    else ()
        # scripting the symlink installation at install time should work
        # for CMake 2.6.x and 2.8.x
        install(CODE "
            if (\"\$ENV{DESTDIR}\" STREQUAL \"\")
                execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
                                ${_filepath}
                                ${_installdir}/${_symname})
            else ()
                execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
                                ${_filepath}
                                \$ENV{DESTDIR}/${_installdir}/${_symname})
            endif ()
        ")
    endif ()
endmacro(InstallSymlink)

if(UNIX)
    SET(CMAKE_INSTALL_PREFIX /usr)
    install(TARGETS smithproxy DESTINATION bin)
    install(FILES man/smithproxy.1 DESTINATION share/man/man1)
    install_if_not_exists(etc/smithproxy.cfg /etc/smithproxy)
    install_if_not_exists(etc/users.cfg /etc/smithproxy)
    install_if_not_exists(etc/users.key /etc/smithproxy)
    install_if_not_exists(etc/smithproxy.startup.cfg /etc/smithproxy)
    install(FILES etc/smithproxy.startup.sh DESTINATION /etc/smithproxy 
                PERMISSIONS 
                    OWNER_READ OWNER_WRITE OWNER_EXECUTE 
                    GROUP_READ GROUP_EXECUTE 
                    WORLD_READ WORLD_EXECUTE 
    )
    install(FILES etc/smithproxy.init DESTINATION /etc/init.d RENAME smithproxy 
            PERMISSIONS 
                    OWNER_READ OWNER_WRITE OWNER_EXECUTE 
                    GROUP_READ GROUP_EXECUTE 
                    WORLD_READ WORLD_EXECUTE 
    )
    install(FILES etc/smithproxy_cli DESTINATION bin 
            PERMISSIONS 
                    OWNER_READ OWNER_WRITE OWNER_EXECUTE 
                    GROUP_READ GROUP_EXECUTE 
                    WORLD_READ WORLD_EXECUTE 
    )
    
    file(GLOB def_certs "etc/certs/default/*.pem")
    install(FILES ${def_certs} DESTINATION /etc/smithproxy/certs/default)
    
    # create CA dir
    install(DIRECTORY DESTINATION /etc/smithproxy/certs/ca)
    InstallSymlink(/etc/ssl/certs /etc/smithproxy/certs/ca/default)
    
    install(FILES man/TESTING_README.txt DESTINATION share/smithproxy/docs)
    
    # backend install in /usr/share/smithproxy/infra/bend/
    install(DIRECTORY infra/bend DESTINATION share/smithproxy/infra)
    # install infra/
    file(GLOB infra_py "infra/*.py" EXCLUDE "infra/smithdog.py")
    install(FILES ${infra_py} DESTINATION share/smithproxy/infra)
    
    file(GLOB infra_exe_py "infra/smithdog.py")
    install(FILES ${infra_exe_py} DESTINATION share/smithproxy/infra 
            PERMISSIONS 
                    OWNER_READ OWNER_WRITE OWNER_EXECUTE 
                    GROUP_READ GROUP_EXECUTE 
                    WORLD_READ WORLD_EXECUTE 
    )

    # portal installation
    install(DIRECTORY infra/portal DESTINATION share/smithproxy/www)
    
    # message: edit defaults and add to init.d to start at boot!
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")
    install(CODE "MESSAGE(\" | Installation complete!                                                                 |\")")
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------|\")")
    install(CODE "MESSAGE(\" |   Hints for minimal setup:                                                             |\")")
    install(CODE "MESSAGE(\" |     1:Edit /etc/smithproxy/smithproxy.startup.cfg                                      |\")")
    install(CODE "MESSAGE(\" |       -  change interface heading to the LAN/internal network you want to inspect.     |\")")
    install(CODE "MESSAGE(\" |     2:Make smithproxy start on boot                                                    |\")")
    install(CODE "MESSAGE(\" |       -  Debian:  update-rc.d smithproxy defaults                                      |\")")
    install(CODE "MESSAGE(\" |     3:Enable smithproxy CLI                                                            |\")")
    install(CODE "MESSAGE(\" |       -  add /usr/bin/smithproxy_cli to /etc/shells, make special user for it, use ssh |\")")
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")
    
    SET(CPACK_GENERATOR "DEB")
    SET(MAJOR_VERSION 0)
    SET(MINOR_VERSION 5)
    SET(PATCH_VERSION 23)
    SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
    SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
    SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
    
    SET(CPACK_PACKAGE_DESCRIPTION "transparent proxy with ssl inspection features")
    SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "tranparent proxy based on TPROXY with SSL inspection, authentication and other features")
    SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ales Stibal <astib@mag0.net>")
    SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libstdc++6 (>= 4.9.0), libssl1.0.0 (>=1.0.0), libconfig++9, libcli1.9 (>=1.9.6)")
    INCLUDE(CPack)

endif()
