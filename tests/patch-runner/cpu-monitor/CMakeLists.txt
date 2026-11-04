cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(smithproxy_cpu_monitor LANGUAGES CXX)
    include(CTest)
endif()

add_library(cpu_monitor_core STATIC core.cpp proc.cpp)
target_compile_features(cpu_monitor_core PUBLIC cxx_std_17)
target_include_directories(cpu_monitor_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/nlohmann/include")
# This directory is three levels below the repository root.
target_compile_options(cpu_monitor_core PRIVATE -Wall -Wextra -Wpedantic)
add_executable(smithproxy-cpu-monitor main.cpp)
target_link_libraries(smithproxy-cpu-monitor PRIVATE cpu_monitor_core)
target_compile_options(smithproxy-cpu-monitor PRIVATE -Wall -Wextra -Wpedantic)

add_executable(cpu-monitor-replay replay.cpp)
target_link_libraries(cpu-monitor-replay PRIVATE cpu_monitor_core)

find_package(Threads REQUIRED)
add_executable(cpu-monitor-proc-tests proc_tests.cpp)
target_link_libraries(cpu-monitor-proc-tests PRIVATE cpu_monitor_core Threads::Threads)
target_link_options(cpu-monitor-proc-tests PRIVATE -Wl,--wrap=read -Wl,--wrap=__read_chk)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME unit.patch_runner_cpu_proc COMMAND cpu-monitor-proc-tests)
set_tests_properties(unit.patch_runner_cpu_proc PROPERTIES LABELS "native;unit" TIMEOUT 15)
add_test(NAME unit.patch_runner_cpu_native_accounting
    COMMAND ${CMAKE_COMMAND} -E env "CPU_MONITOR_REPLAY=$<TARGET_FILE:cpu-monitor-replay>"
    ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/../test-cpu-monitor-native-accounting.py")
set_tests_properties(unit.patch_runner_cpu_native_accounting
    PROPERTIES LABELS "native;unit" TIMEOUT 90 RUN_SERIAL TRUE)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    foreach(suite monitor faults diagnostics)
        if(suite STREQUAL "monitor")
            set(script "test-cpu-monitor.py")
        else()
            set(script "test-cpu-monitor-${suite}.py")
        endif()
        if(suite STREQUAL "diagnostics")
            set(test_name "extended.patch_runner_cpu_diagnostics")
            set(labels "native;extended")
            set(deadline 600)
        else()
            set(test_name "unit.patch_runner_cpu_${suite}")
            set(labels "native;unit")
            set(deadline 45)
        endif()
        add_test(NAME ${test_name} COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/../${script}")
        set_tests_properties(${test_name} PROPERTIES LABELS "${labels}" TIMEOUT ${deadline} RUN_SERIAL TRUE
            ENVIRONMENT "CPU_MONITOR_BINARY=$<TARGET_FILE:smithproxy-cpu-monitor>")
    endforeach()
endif()

# The real-proxy test is opt-in for standalone builds and never uses host routes.
set(CPU_MONITOR_PROXY_BINARY "" CACHE FILEPATH "Existing Smithproxy binary for isolated CPU integration")
set(cpu_proxy "${CPU_MONITOR_PROXY_BINARY}")
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(cpu_proxy "$<TARGET_FILE:smithproxy>")
endif()
if(cpu_proxy)
    find_program(CPU_MONITOR_UNSHARE unshare REQUIRED)
    add_test(NAME integration.patch_runner_cpu_real_proxy
        COMMAND "${CPU_MONITOR_UNSHARE}" --user --map-current-user --keep-caps --net
        "${CMAKE_CURRENT_SOURCE_DIR}/../run-cpu-monitor-real-proxy.sh"
        "${CMAKE_CURRENT_BINARY_DIR}/real-proxy-results"
        "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../test-cpu-monitor-real-proxy.py"
        --local --smithproxy "${cpu_proxy}" --monitor "$<TARGET_FILE:smithproxy-cpu-monitor>"
        --source "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
    set_tests_properties(integration.patch_runner_cpu_real_proxy PROPERTIES
        LABELS "native;integration;privileged;extended" TIMEOUT 180 RUN_SERIAL TRUE)
endif()

# ProxyNightmare remains an explicit dependency.  Its runner and scenarios are
# consumed in place for local CTest; the patch-runner stages both for remotes.
set(PROXY_NIGHTMARE_ROOT "" CACHE PATH "ProxyNightmare source/build root")
if(cpu_proxy AND PROXY_NIGHTMARE_ROOT)
    if(NOT EXISTS "${PROXY_NIGHTMARE_ROOT}/build/pn")
        message(FATAL_ERROR "ProxyNightmare binary is missing: ${PROXY_NIGHTMARE_ROOT}/build/pn")
    endif()
    add_test(NAME integration.patch_runner_proxy_nightmare_lifecycle
        COMMAND "${CPU_MONITOR_UNSHARE}" --user --map-root-user --keep-caps
        --mount --propagation private --net
        "${CMAKE_CURRENT_SOURCE_DIR}/../run-proxy-nightmare-lifecycle.sh"
        "${CMAKE_CURRENT_BINARY_DIR}/proxy-nightmare-results"
        "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../test-proxy-nightmare-lifecycle.py"
        --source "${CMAKE_CURRENT_SOURCE_DIR}/../../.." --smithproxy "${cpu_proxy}"
        --monitor "$<TARGET_FILE:smithproxy-cpu-monitor>"
        --proxy-nightmare "${PROXY_NIGHTMARE_ROOT}")
    set_tests_properties(integration.patch_runner_proxy_nightmare_lifecycle PROPERTIES
        LABELS "native;integration;privileged;extended;lifecycle" TIMEOUT 300 RUN_SERIAL TRUE)
endif()
