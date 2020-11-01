cmake_minimum_required(VERSION 3.4)

project(ccord LANGUAGES C)

message(STATUS "Building with ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} on ${CMAKE_SYSTEM} for platform ${CMAKE_SYSTEM_NAME}")

add_executable(ccord
    src/http.c
    src/url_parser.c
    src/url.c
)

target_include_directories(ccord PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/build
)

set_target_properties(ccord PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)

add_custom_target (llhttp ALL
    COMMAND cd  ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp && npm i && make
)

find_package(GnuTLS REQUIRED)

find_library(UV_PATH uv REQUIRED)

message(STATUS "Found libuv: ${UV_PATH}")

target_link_libraries(ccord GnuTLS::GnuTLS ${UV_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/build/libllhttp.a)

add_dependencies(ccord llhttp)