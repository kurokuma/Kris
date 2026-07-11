cmake_minimum_required(VERSION 3.24)
project(NativeSafeRuntimeProbe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(NativeSafeRuntimeProbe main.cpp)
target_compile_definitions(NativeSafeRuntimeProbe PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(NativeSafeRuntimeProbe PRIVATE advapi32 ole32 ws2_32)
