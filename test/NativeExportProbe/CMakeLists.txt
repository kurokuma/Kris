cmake_minimum_required(VERSION 3.24)
project(NativeExportProbe LANGUAGES CXX)

add_library(NativeExportProbe SHARED main.cpp)
target_compile_features(NativeExportProbe PRIVATE cxx_std_20)
target_compile_definitions(NativeExportProbe PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
