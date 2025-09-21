include(fetchcontent)

cmake_minimum_required(VERSION 3.31)
project(libhat_ida)
set(CMAKE_CXX_STANDARD 23)

FetchContent_Declare(
    libhat
    GIT_REPOSITORY https://github.com/BasedInc/libhat.git
    GIT_TAG master
)

FetchContent_MakeAvailable(libhat)

file(GLOB_RECURSE src CONFIGURE_DEPENDS "src/*.cpp" "src/*.hpp")
add_library(libhat_ida SHARED ${src})

target_link_libraries(libhat_ida PRIVATE ${CMAKE_SOURCE_DIR}/ida-sdk/lib/ida.lib libhat)
target_include_directories(libhat_ida PRIVATE ./ida-sdk/include/)