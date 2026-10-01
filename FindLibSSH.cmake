find_path(LIBSSH_INCLUDE_DIR
        NAMES libssh/libssh.h
        PATH_SUFFIXES include)

find_library(LIBSSH_LIBRARY
        NAMES ssh libssh
        PATH_SUFFIXES lib lib64 lib/x86_64-linux-gnu)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibSSH
        REQUIRED_VARS LIBSSH_LIBRARY LIBSSH_INCLUDE_DIR)

if(LibSSH_FOUND AND NOT TARGET LibSSH::LibSSH)
    add_library(LibSSH::LibSSH UNKNOWN IMPORTED)
    set_target_properties(LibSSH::LibSSH PROPERTIES
            IMPORTED_LOCATION "${LIBSSH_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH_INCLUDE_DIR}")
endif()

mark_as_advanced(LIBSSH_INCLUDE_DIR LIBSSH_LIBRARY)
