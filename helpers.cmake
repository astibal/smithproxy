cmake_minimum_required(VERSION 3.0)

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

