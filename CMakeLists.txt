cmake_minimum_required(VERSION 3.16)
project(c-http LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF) # strict ISO C, no GNU extensions
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # for clangd / clang-tidy

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

option(USE_SANITIZERS "build with ASan/UBSan in Debug builds" ON)

# ---------------------------------------------------------------------------
# dependencies (git submodules; initialize with: git submodule update --init)
# ---------------------------------------------------------------------------
add_subdirectory(vendor/cargs EXCLUDE_FROM_ALL)

# ---------------------------------------------------------------------------
# first-party code: strict warnings + feature macros
# ---------------------------------------------------------------------------
add_library(c_http_options INTERFACE)
target_compile_definitions(c_http_options INTERFACE _POSIX_C_SOURCE=200809L)
target_compile_options(c_http_options INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wdouble-promotion
  -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes
  -Wnull-dereference -Wvla)

function(c_http_add_executable target)
  add_executable(${target} ${ARGN})
  target_link_libraries(${target} PRIVATE c_http_options)
  if(USE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined
      -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# targets
# ---------------------------------------------------------------------------
c_http_add_executable(c-http src/main.c src/args.c src/http.c)
target_link_libraries(c-http PRIVATE cargs)
# vendor headers are SYSTEM includes: their warnings are not ours
target_include_directories(c-http SYSTEM PRIVATE vendor/cargs/include)

# ---------------------------------------------------------------------------
# tests (ctest)
# ---------------------------------------------------------------------------
enable_testing()
c_http_add_executable(test_example tests/test_example.c)
add_test(NAME example COMMAND test_example)

# ---------------------------------------------------------------------------
# development helpers
# ---------------------------------------------------------------------------
file(GLOB C_HTTP_SOURCES CONFIGURE_DEPENDS src/*.c src/*.h tests/*.c tests/*.h)
add_custom_target(format
  COMMAND clang-format -i ${C_HTTP_SOURCES})
add_custom_target(format-check
  COMMAND clang-format --dry-run --Werror ${C_HTTP_SOURCES})
add_custom_target(lint
  COMMAND clang-tidy -p ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/src/main.c)