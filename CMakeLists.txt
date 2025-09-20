include(fetchcontent)

cmake_minimum_required(VERSION 3.31)
project(libhat_ida)
set(CMAKE_CXX_STANDARD 23)

FetchContent_Declare(
        idasdk
        GIT_REPOSITORY https://github.com/HexRaysSA/ida-sdk.git
        GIT_TAG v9.2
)

FetchContent_MakeAvailable(idasdk)

FetchContent_Declare(
    libhat
    GIT_REPOSITORY https://github.com/BasedInc/libhat.git
    GIT_TAG master
)

FetchContent_MakeAvailable(libhat)

file(GLOB_RECURSE src CONFIGURE_DEPENDS "src/*.cpp" "src/*.hpp")
add_library(libhat_ida SHARED ${src})

add_compile_definitions("__EA64__")

target_link_libraries(libhat_ida PRIVATE ${idasdk_SOURCE_DIR}/src/lib/x64_win_vc_64/ida.lib libhat)
target_include_directories(libhat_ida PRIVATE ${idasdk_SOURCE_DIR}/src/include/)