# Run at build time: committing or checking out a branch does not necessarily
# rerun CMake configuration. configure_file only rewrites changed content.
function(status_git_version directory result)
    set(version "")
    if(EXISTS "${directory}/.git")
        execute_process(COMMAND git describe --tags --always --dirty
            WORKING_DIRECTORY "${directory}"
            OUTPUT_VARIABLE version OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE status ERROR_QUIET)
        if(NOT status EQUAL 0)
            set(version "")
        endif()
    endif()
    string(REPLACE "\\" "\\\\" version "${version}")
    string(REPLACE "\"" "\\\"" version "${version}")
    set(${result} "${version}" PARENT_SCOPE)
endfunction()

status_git_version("${SOURCE_DIR}" SX_STATUS_VERSION)
status_git_version("${SOURCE_DIR}/socle" SOCLE_STATUS_VERSION)
configure_file("${SOURCE_DIR}/src/service/status_build_info.hpp.in"
    "${OUTPUT_FILE}" @ONLY)
