# Keep the vendored QPACK implementation isolated behind one project target.
# Consumers should link smithproxy_qpack and include <lsqpack.h>; no system
# ls-qpack or xxHash package is required.
add_library(smithproxy_qpack STATIC
        lsqpack.c
        deps/xxhash/xxhash.c
)

target_include_directories(smithproxy_qpack
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/xxhash
)

set_target_properties(smithproxy_qpack PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS YES
        POSITION_INDEPENDENT_CODE YES
)

# These warnings match upstream's supported build. Third-party warnings are
# deliberately not promoted to errors by Smithproxy's own compiler policy.
if(NOT MSVC)
    target_compile_options(smithproxy_qpack PRIVATE
            -Wall
            -Wextra
            -Wno-unused-parameter
            -Wno-implicit-fallthrough
    )
endif()
