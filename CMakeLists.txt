cmake_minimum_required(VERSION 3.16)
project(c-http
  VERSION 0.9.0
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

find_package(Threads REQUIRED)

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
  src/c_http_static.c
  src/c_http_tpl.c
  src/c_http_ws.c
)
target_include_directories(c_http PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(c_http PUBLIC ZLIB::ZLIB Threads::Threads)
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
      ${CMAKE_CURRENT_SOURCE_DIR}/include/c_http_static.h
      ${CMAKE_CURRENT_SOURCE_DIR}/include/c_http_tpl.h
      ${CMAKE_CURRENT_SOURCE_DIR}/include/c_http_ws.h
      ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http.c
      ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http_encoder.c
      ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http_static.c
      ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http_tpl.c
      ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http_ws.c
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/amalgamate.py
    COMMENT "Generating single-header amalgamation"
  )
endif()

# ---------------------------------------------------------------------------
# ctmpl: .thtml -> C generator (build tool, not installed)
# ---------------------------------------------------------------------------
if(C_HTTP_IS_TOPLEVEL)
  add_executable(ctmpl tools/ctmpl.c tools/ctmpl_main.c)
  c_http_apply_options(ctmpl)
endif()

# ---------------------------------------------------------------------------
# examples (only when top-level)
# ---------------------------------------------------------------------------
if(C_HTTP_IS_TOPLEVEL AND C_HTTP_BUILD_EXAMPLES)
  add_subdirectory(vendor/cargs EXCLUDE_FROM_ALL)

  # Regeneration of the example template: ctmpl compiles home.thtml
  # into home_templ.[ch] (committed, like templ's _templ.go files).
  # Rebuilds when the .thtml or the generator changes.
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/examples/tpl/home_templ.h
           ${CMAKE_CURRENT_SOURCE_DIR}/examples/tpl/home_templ.c
    COMMAND $<TARGET_FILE:ctmpl>
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/tpl/home.thtml
    DEPENDS ctmpl ${CMAKE_CURRENT_SOURCE_DIR}/examples/tpl/home.thtml
    COMMENT "ctmpl: regenerating examples/tpl/home_templ.[ch]"
  )
  add_custom_target(ctmpl_generate
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/examples/tpl/home_templ.h
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/tpl/home_templ.c)

  add_executable(c-http-example examples/main.c examples/args.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/tpl/home_templ.c)
  target_link_libraries(c-http-example PRIVATE c_http cargs)
  c_http_apply_options(c-http-example)
  target_include_directories(c-http-example SYSTEM PRIVATE vendor/cargs/include)
  target_include_directories(c-http-example PRIVATE examples)
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

  # echte Library-Tests (Integration ueber Sockets, laeuft in einem Thread)
  add_executable(test_http tests/test_http.c)
  target_link_libraries(test_http PRIVATE c_http Threads::Threads)
  c_http_apply_options(test_http)
  add_test(NAME http COMMAND test_http)

  add_executable(test_ws tests/test_websockets.c)
  target_link_libraries(test_ws PRIVATE c_http Threads::Threads)
  c_http_apply_options(test_ws)
  add_test(NAME ws COMMAND test_ws)

  add_executable(test_tpl tests/test_template.c)
  target_link_libraries(test_tpl PRIVATE c_http Threads::Threads)
  c_http_apply_options(test_tpl)
  add_test(NAME tpl COMMAND test_tpl)

  add_executable(test_ctmpl tests/test_ctmpl.c tools/ctmpl.c)
  c_http_apply_options(test_ctmpl)
  target_include_directories(test_ctmpl PRIVATE tools)
  add_test(NAME ctmpl COMMAND test_ctmpl)
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
  include/*.h src/*.c tools/*.c tools/*.h
  examples/*.c examples/*.h examples/tpl/*.h
  tests/*.c tests/*.h)
list(FILTER C_HTTP_SOURCES EXCLUDE REGEX "_templ\\.[ch]$")
add_custom_target(format
  COMMAND clang-format -i ${C_HTTP_SOURCES})
add_custom_target(format-check
  COMMAND clang-format --dry-run --Werror ${C_HTTP_SOURCES})
add_custom_target(lint
  COMMAND clang-tidy -p ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src/c_http.c)
