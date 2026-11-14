# Schema migrations must work without a legacy template directory. Generate
# migration payloads from the maintained templates; do not duplicate HTML in C++.
set(schema_1051_names tls_override_form tls_reason tls_certificate_field
    tls_certificate_details tls_replacement_error tls_redirect tls_redirect_top)
set(schema_header "#pragma once\n#include <map>\n#include <string>\nnamespace sx::cfg {\ninline std::map<std::string, std::string> schema_1051_resources() {\nreturn {\n")
foreach(name IN LISTS schema_1051_names)
    set(input "${PROJECT_SOURCE_DIR}/etc/msg/en/${name}.txt")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${input}")
    file(READ "${input}" content)
    string(FIND "${content}" ")sx_schema\"" delimiter_position)
    if(NOT delimiter_position EQUAL -1)
        message(FATAL_ERROR "Schema resource contains reserved raw-string delimiter: ${input}")
    endif()
    string(APPEND schema_header "{\"templates/replacement/en/${name}.txt\", R\"sx_schema(${content})sx_schema\"},\n")
endforeach()
string(APPEND schema_header "};\n}\n}\n")
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/generated")
file(CONFIGURE OUTPUT "${PROJECT_BINARY_DIR}/generated/schema_resources.hpp"
    CONTENT "${schema_header}" @ONLY)
include_directories("${PROJECT_BINARY_DIR}/generated")
