include(FetchContent)

cmake_minimum_required(VERSION 3.29)
project(libhat_ida)
set(CMAKE_CXX_STANDARD 23)

FetchContent_Declare(
    idasdk
    GIT_REPOSITORY https://github.com/HexRaysSA/ida-sdk.git
    GIT_TAG v9.2
)

FetchContent_Declare(
    libhat
    GIT_REPOSITORY https://github.com/BasedInc/libhat.git
    GIT_TAG 2d24bcf541465f1c53ed546100feb3a8e10a5d42 # v0.8.0+1
)

FetchContent_MakeAvailable(idasdk libhat)

file(GLOB_RECURSE src CONFIGURE_DEPENDS "src/*.cpp" "src/*.hpp")
add_library(libhat_ida SHARED ${src})
target_compile_definitions(libhat_ida PRIVATE "USE_STANDARD_FILE_FUNCTIONS")

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(IDASDK_LIB_PATH_PARTIAL "x64_win_vc_64/ida.lib")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(IDASDK_LIB_PATH_PARTIAL "x64_linux_gcc_64/libida.so")
else()
    message(FATAL_ERROR "Unsupported target system.")
endif()

target_link_libraries(libhat_ida PRIVATE ${idasdk_SOURCE_DIR}/src/lib/${IDASDK_LIB_PATH_PARTIAL} libhat)
target_include_directories(libhat_ida PRIVATE ${idasdk_SOURCE_DIR}/src/include/)
target_compile_definitions(libhat_ida PRIVATE __EA64__)
