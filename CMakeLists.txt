cmake_minimum_required(VERSION 3.16)
project(c-http
  VERSION 0.1.0
  LANGUAGES C
  DESCRIPTION "A minimal HTTP server library in C"
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

option(C_HTTP_BUILD_EXAMPLES "Build example server" ON)
option(C_HTTP_BUILD_TESTS    "Build unit tests" ON)
option(USE_SANITIZERS        "Build with ASan/UBSan in Debug" ON)
option(C_HTTP_AMALGAMATE     "Generate single-header amalgamation" OFF)

# Is this repo the top-level project, or consumed via add_subdirectory?
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(C_HTTP_IS_TOPLEVEL ON)
else()
  set(C_HTTP_IS_TOPLEVEL OFF)
endif()

# ---------------------------------------------------------------------------
# dependencies
# ---------------------------------------------------------------------------
find_package(ZLIB REQUIRED)

# ---------------------------------------------------------------------------
# compile options shared by examples and tests
# ---------------------------------------------------------------------------
add_library(c_http_options INTERFACE)
target_compile_definitions(c_http_options INTERFACE _POSIX_C_SOURCE=200809L)
target_compile_options(c_http_options INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wdouble-promotion
  -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes
  -Wnull-dereference -Wvla)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(c_http_options INTERFACE NDEBUG)
endif()

function(c_http_apply_options target)
  target_link_libraries(${target} PRIVATE c_http_options)
  if(USE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined
      -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# library target
# ---------------------------------------------------------------------------
add_library(c_http STATIC
  src/c_http.c
  src/c_http_encoder.c
)
target_include_directories(c_http PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(c_http PUBLIC ZLIB::ZLIB)
target_compile_definitions(c_http PUBLIC _POSIX_C_SOURCE=200809L)
target_compile_options(c_http PRIVATE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wdouble-promotion
  -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes
  -Wnull-dereference -Wvla)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(c_http PUBLIC NDEBUG)
endif()
if(USE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(c_http PRIVATE -fsanitize=address,undefined
    -fno-omit-frame-pointer)
  target_link_options(c_http PRIVATE -fsanitize=address,undefined)
endif()

add_library(c_http::c_http ALIAS c_http)

# ---------------------------------------------------------------------------
# single-header amalgamation
# ---------------------------------------------------------------------------
if(C_HTTP_AMALGAMATE)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_custom_target(c_http_amalgamate
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/amalgamate.py
            --output ${CMAKE_CURRENT_BINARY_DIR}/c_http_single.h
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/include/c_http.h
      ${CMAKE_CURRENT_SOURCE_DIR}/include/c_http_assert.h
      ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http.c
      ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http_encoder.c
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/amalgamate.py
    COMMENT "Generating single-header amalgamation"
  )
endif()

# ---------------------------------------------------------------------------
# examples (only when top-level)
# ---------------------------------------------------------------------------
if(C_HTTP_IS_TOPLEVEL AND C_HTTP_BUILD_EXAMPLES)
  add_subdirectory(vendor/cargs EXCLUDE_FROM_ALL)
  add_executable(c-http-example examples/main.c examples/args.c)
  target_link_libraries(c-http-example PRIVATE c_http cargs)
  c_http_apply_options(c-http-example)
  target_include_directories(c-http-example SYSTEM PRIVATE vendor/cargs/include)
endif()

# ---------------------------------------------------------------------------
# tests (only when top-level)
# ---------------------------------------------------------------------------
if(C_HTTP_IS_TOPLEVEL AND C_HTTP_BUILD_TESTS)
  enable_testing()
  add_executable(test_example tests/test_example.c)
  target_link_libraries(test_example PRIVATE c_http)
  c_http_apply_options(test_example)
  add_test(NAME example COMMAND test_example)
endif()

# ---------------------------------------------------------------------------
# install + export (for find_package(c-http))
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS c_http
  EXPORT c_httpTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT c_httpTargets
  FILE c_httpTargets.cmake
  NAMESPACE c_http::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/c-http
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/c-httpConfig.cmake
  "include(\"\${CMAKE_CURRENT_LIST_DIR}/c_httpTargets.cmake\")\n")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/c-httpConfig.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/c-http)

# ---------------------------------------------------------------------------
# development helpers
# ---------------------------------------------------------------------------
file(GLOB C_HTTP_SOURCES CONFIGURE_DEPENDS
  include/*.h src/*.c examples/*.c examples/*.h tests/*.c tests/*.h)
add_custom_target(format
  COMMAND clang-format -i ${C_HTTP_SOURCES})
add_custom_target(format-check
  COMMAND clang-format --dry-run --Werror ${C_HTTP_SOURCES})
add_custom_target(lint
  COMMAND clang-tidy -p ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/src/c_http.c)