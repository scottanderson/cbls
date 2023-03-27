cmake_minimum_required(VERSION 3.10)

project(cbls)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_STANDARD 99)
add_compile_options(-Werror)

# Collect all source files recursively
file(GLOB_RECURSE SOURCES
    "${PROJECT_SOURCE_DIR}/CBLS/src/*.c"
    "${PROJECT_SOURCE_DIR}/CBLS/src/*.cpp"
    "${PROJECT_SOURCE_DIR}/CBLS/src/*.h")

# Set the output directory for the binaries
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Create executable from all collected source files
add_executable(cbls ${SOURCES})

# Link against the required libraries
target_link_libraries(cbls gmp)

