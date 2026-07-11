cmake_minimum_required(VERSION 3.24)
project(MRTWNative LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

include(FetchContent)
FetchContent_Declare(
  minhook
  GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
  GIT_TAG v1.3.4
)
FetchContent_MakeAvailable(minhook)

add_library(hook_x64 SHARED
  hook/hook.cpp
  hook/pipe_client.cpp
  hook/api_hooks_file.cpp
  hook/api_hooks_registry.cpp
  hook/api_hooks_process.cpp
  hook/api_hooks_network.cpp
  hook/api_hooks_credential.cpp
  hook/api_hooks_anti_analysis.cpp
  hook/api_hooks_module.cpp
  hook/api_hooks_discovery.cpp
  hook/api_hooks_token.cpp
  hook/api_hooks_impact.cpp
  hook/api_hooks_stealer.cpp
  hook/api_hooks_tamper.cpp
  hook/api_hooks_ipc.cpp
  hook/api_hooks_com_wmi.cpp
  hook/api_hooks_service_system.cpp
  hook/api_hooks_environment.cpp
  hook/api_hooks_evasion_extra.cpp
)

target_compile_definitions(hook_x64 PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX MRTW_HOOK_EXPORTS)
target_include_directories(hook_x64 PRIVATE hook ${minhook_SOURCE_DIR}/include)
target_link_libraries(hook_x64 PRIVATE minhook advapi32 winhttp wininet ws2_32 dnsapi crypt32 dbghelp psapi shell32 bcrypt user32 gdi32 amsi ole32 iphlpapi)
set_target_properties(hook_x64 PROPERTIES OUTPUT_NAME "hook_x64")

add_executable(injector_x64
  injector/main.cpp
  injector/injector.cpp
)

target_compile_definitions(injector_x64 PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(injector_x64 PRIVATE injector)
set_target_properties(injector_x64 PROPERTIES OUTPUT_NAME "injector_x64")
