cmake_minimum_required(VERSION 3.22)
project(guardian_fs C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(guardian_fs
    src/entropy.c
    src/detector.c
    src/canary.c
    src/zfs_snap.c
    src/ring_buffer.c
    src/mitigation.c
    src/analyzer.c
    src/guardian_fs.c
)

target_include_directories(guardian_fs PRIVATE ${FUSE3_INCLUDE_DIRS})
target_link_libraries(guardian_fs PRIVATE ${FUSE3_LIBRARIES} pthread m)
target_link_directories(guardian_fs PRIVATE ${FUSE3_LIBRARY_DIRS})

option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/unit)
endif()
