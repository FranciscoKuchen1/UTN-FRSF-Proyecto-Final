# tests/unit/CMakeLists.txt — Build system for Guardian FS unit tests
# Compiles each test_*.c against the core library source files.

# Build guardian core sources as an OBJECT library (no main function)
# NOTE: analyzer.c is excluded because it has extern references to evbuf/detector
# defined in guardian_fs.c. test_analyzer (in tests/) has its own stubs.
add_library(guardian_obj OBJECT
    ${CMAKE_SOURCE_DIR}/src/entropy.c
    ${CMAKE_SOURCE_DIR}/src/detector.c
    ${CMAKE_SOURCE_DIR}/src/canary.c
    ${CMAKE_SOURCE_DIR}/src/ring_buffer.c
    ${CMAKE_SOURCE_DIR}/src/mitigation.c
)

target_include_directories(guardian_obj PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(guardian_obj PRIVATE _GNU_SOURCE)
set_target_properties(guardian_obj PROPERTIES
    C_STANDARD 17
    C_STANDARD_REQUIRED ON
)

# Helper macro to define a test
macro(add_unit_test TEST_NAME)
    add_executable(${TEST_NAME}
        ${TEST_NAME}.c
        $<TARGET_OBJECTS:guardian_obj>
    )
    target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(${TEST_NAME} PRIVATE pthread m)
    target_compile_options(${TEST_NAME} PRIVATE -Wall -Wextra)
    set_target_properties(${TEST_NAME} PROPERTIES
        C_STANDARD 17
        C_STANDARD_REQUIRED ON
    )

    add_test(
        NAME ${TEST_NAME}
        COMMAND ${TEST_NAME}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests/unit
    )
endmacro()

# --- Test executables ---

add_unit_test(test_entropy)
add_unit_test(test_detector)
add_unit_test(test_ring_buffer)
add_unit_test(test_canary)
add_unit_test(test_mitigation)

# test_analyzer is separate because it needs stubs for extern globals
add_executable(test_analyzer
    ${CMAKE_SOURCE_DIR}/tests/test_analyzer.c
    ${CMAKE_SOURCE_DIR}/src/ring_buffer.c
    ${CMAKE_SOURCE_DIR}/src/detector.c
    ${CMAKE_SOURCE_DIR}/src/entropy.c
)
target_include_directories(test_analyzer PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_analyzer PRIVATE pthread m)
target_compile_options(test_analyzer PRIVATE -Wall -Wextra)
set_target_properties(test_analyzer PROPERTIES
    C_STANDARD 17
    C_STANDARD_REQUIRED ON
)
add_test(
    NAME test_analyzer
    COMMAND test_analyzer
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests/unit
)
