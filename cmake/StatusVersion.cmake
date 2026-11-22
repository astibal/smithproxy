# Run at build time so new tags and commits do not require reconfiguration.
# Only reachable numeric release tags qualify; custom labels never become a
# product version. git describe chooses the nearest qualifying ancestor tag.
function(status_git_version directory fallback result)
    set(version "${fallback}")
    if(EXISTS "${directory}/.git")
        execute_process(COMMAND git tag --merged HEAD
            WORKING_DIRECTORY "${directory}"
            OUTPUT_VARIABLE tags OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE status ERROR_QUIET)
        set(matches)
        if(status EQUAL 0)
            string(REPLACE "\n" ";" tags "${tags}")
            foreach(tag IN LISTS tags)
                if(tag MATCHES "^v?[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?$")
                    list(APPEND matches --match "${tag}")
                endif()
            endforeach()
        endif()
        if(matches)
            execute_process(COMMAND git describe --tags --abbrev=0 ${matches} HEAD
                WORKING_DIRECTORY "${directory}"
                OUTPUT_VARIABLE release_tag OUTPUT_STRIP_TRAILING_WHITESPACE
                RESULT_VARIABLE status ERROR_QUIET)
            if(status EQUAL 0)
                string(REGEX REPLACE "^v" "" version "${release_tag}")
            endif()
        endif()
        if(BUILD_CONFIG STREQUAL "Debug")
            execute_process(COMMAND git rev-parse --short=8 HEAD
                WORKING_DIRECTORY "${directory}"
                OUTPUT_VARIABLE commit OUTPUT_STRIP_TRAILING_WHITESPACE
                RESULT_VARIABLE status ERROR_QUIET)
            if(status EQUAL 0)
                string(APPEND version "-${commit}")
            endif()
        endif()
    endif()
    set(${result} "${version}" PARENT_SCOPE)
endfunction()

# Source archives and shallow clones without release tags retain their declared
# numeric version. Do not invent a tag or use an unrelated checkout's Git data.
file(STRINGS "${SOURCE_DIR}/src/main.hpp" smith_version_line REGEX "^#define SMITH_VERSION ")
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?" smith_fallback "${smith_version_line}")
file(STRINGS "${SOURCE_DIR}/socle/socle.hpp" socle_version_line REGEX "^#define SOCLE_VERSION ")
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?" socle_fallback "${socle_version_line}")
status_git_version("${SOURCE_DIR}" "${smith_fallback}" SX_STATUS_VERSION)
status_git_version("${SOURCE_DIR}/socle" "${socle_fallback}" SOCLE_STATUS_VERSION)
configure_file("${SOURCE_DIR}/src/service/status_build_info.hpp.in"
    "${OUTPUT_FILE}" @ONLY)
