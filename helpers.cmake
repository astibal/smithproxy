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

# Preserve deployed private keys during upgrades while enforcing their mode.
function(install_secret_if_not_exists src dest)
    if(NOT IS_ABSOLUTE "${src}")
        set(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
    endif()
    get_filename_component(src_name "${src}" NAME)
    if(NOT IS_ABSOLUTE "${dest}")
        set(dest "${CMAKE_INSTALL_PREFIX}/${dest}")
    endif()
    find_program(chmod_program chmod)
    if(NOT chmod_program)
        message(FATAL_ERROR "chmod is required to install private keys")
    endif()

    install(CODE "
        if(IS_SYMLINK \"\$ENV{DESTDIR}${dest}/${src_name}\")
            message(FATAL_ERROR
                    \"Refusing private-key symlink: \$ENV{DESTDIR}${dest}/${src_name}\")
        elseif(IS_DIRECTORY \"\$ENV{DESTDIR}${dest}/${src_name}\")
            message(FATAL_ERROR
                    \"Private-key destination is a directory: \$ENV{DESTDIR}${dest}/${src_name}\")
        elseif(NOT EXISTS \"\$ENV{DESTDIR}${dest}/${src_name}\")
            message(STATUS \"Installing: \$ENV{DESTDIR}${dest}/${src_name}\")
            file(INSTALL DESTINATION \"\$ENV{DESTDIR}${dest}\" TYPE FILE
                 FILES \"${src}\" PERMISSIONS OWNER_READ OWNER_WRITE)
        else()
            message(STATUS \"Restricting: \$ENV{DESTDIR}${dest}/${src_name}\")
            execute_process(
                COMMAND \"${chmod_program}\" 0600 --
                        \"\$ENV{DESTDIR}${dest}/${src_name}\"
                RESULT_VARIABLE chmod_result
                ERROR_VARIABLE chmod_error)
            if(chmod_result)
                message(FATAL_ERROR \"Unable to restrict private-key permissions: \${chmod_error}\")
            endif()
        endif()
    ")
endfunction(install_secret_if_not_exists)

function (create_dir _dirpath)
    install(CODE "
        message(STATUS \"Directory : ${_dirpath}\")
        execute_process(COMMAND \"${CMAKE_COMMAND}\" -E make_directory ${_dirpath})
    ")
endfunction (create_dir)


function(create_symlink _src _dst)
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink  ${_src} ${_dst}
            RESULT_VARIABLE res
            ERROR_VARIABLE err)
    if(res)
        message(">> installing git hooks failed: ${err}")
    endif()
endfunction()


function(create_git_hooks)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git/hooks/pre-commit")
        message(">> Installing git hooks")
        create_symlink(../../.git_pre-commit ${CMAKE_CURRENT_SOURCE_DIR}/.git/hooks/pre-commit)
    else()
        message(">> Git hooks present")
    endif()
endfunction()

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
