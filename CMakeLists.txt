cmake_minimum_required(VERSION 3.24)
project(MermaidJsWebView LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(MERMAIDJS_WEB_BUILD "Build MermaidJsWebView in web (no local CLI) mode" OFF)

# --- stable outputs into <repo>/dist ---
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_SOURCE_DIR}/dist)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  ${CMAKE_SOURCE_DIR}/dist)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${CMAKE_SOURCE_DIR}/dist)
endif()

# build the WLX as a MODULE so it produces a single DLL
add_library(MermaidJsWebView MODULE
    src/mermaidjs_wlx_ev2.cpp
)

target_compile_features(MermaidJsWebView PRIVATE cxx_std_17)
target_compile_definitions(MermaidJsWebView PRIVATE UNICODE _UNICODE NOMINMAX)
if(MERMAIDJS_WEB_BUILD)
    target_compile_definitions(MermaidJsWebView PRIVATE MERMAIDJS_WEB_BUILD=1)
else()
    target_compile_definitions(MermaidJsWebView PRIVATE MERMAIDJS_WEB_BUILD=0)
endif()
target_include_directories(MermaidJsWebView PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/WebView2/build/native/include
)
target_link_libraries(MermaidJsWebView PRIVATE shlwapi)

# Name it exactly as TC expects and use the .wlx64 extension
set_target_properties(MermaidJsWebView PROPERTIES
    OUTPUT_NAME "MermaidJsWebView"
    PREFIX ""                 # no "lib" prefix anywhere
    SUFFIX ".wlx64"           # produce MermaidJsWebView.wlx64 instead of .dll
)
