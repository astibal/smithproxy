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

add_executable(smithproxy smithproxy.cpp mitmhost.cpp mitmproxy.cpp cfgapi.cpp cidr.cpp policy.cpp daemon.cpp sockshostcx.cpp socksproxy.cpp cmdserver.cpp cfgapi_auth.cpp)

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


if(UNIX)
    SET(CMAKE_INSTALL_PREFIX /usr)
    install(TARGETS smithproxy DESTINATION bin)
    install(FILES man/smithproxy.1 DESTINATION share/man/man1)
    install_if_not_exists(etc/smithproxy.cfg /etc/smithproxy)
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
    file(GLOB def_certs "etc/certs/default/*.pem")
    install(FILES ${def_certs} DESTINATION /etc/smithproxy/certs/default)
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
    install(DIRECTORY infra/portal DESTINATION /var/www/smithproxy)
    
    # message: edit defaults and add to init.d to start at boot!
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")
    install(CODE "MESSAGE(\" | Installation complete!                                                                 |\")")
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------|\")")
    install(CODE "MESSAGE(\" |   Hints for minimal setup:                                                             |\")")
    install(CODE "MESSAGE(\" |     1:Edit /etc/smithproxy/smithproxy.startup.cfg                                      |\")")
    install(CODE "MESSAGE(\" |          -  change interface heading to the LAN/internal network you want to inspect.  |\")")
    install(CODE "MESSAGE(\" |     2:Make smithproxy start on boot                                                    |\")")
    install(CODE "MESSAGE(\" |          -  Debian:  update-rc.d smithproxy defaults                                   |\")")
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")

endif()
