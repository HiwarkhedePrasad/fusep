cmake_minimum_required(VERSION 3.20)
project(fuseviz-daemon VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fsanitize=address")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# libbpf (optional — daemon falls back to synthetic events without it)
find_library(LIBBPF_LIB bpf HINTS /usr/lib /usr/local/lib)
find_path(LIBBPF_INC bpf/libbpf.h HINTS /usr/include /usr/local/include)
if(LIBBPF_LIB AND LIBBPF_INC)
    set(HAVE_LIBBPF TRUE)
    add_compile_definitions(HAVE_LIBBPF)
    message(STATUS "libbpf found — eBPF tracing enabled")
else()
    set(HAVE_LIBBPF FALSE)
    message(STATUS "libbpf NOT found — eBPF tracing disabled, using fallback")
endif()

# SQLite3
find_library(SQLITE3_LIB sqlite3 HINTS /usr/lib /usr/local/lib)
find_path(SQLITE3_INC sqlite3.h HINTS /usr/include /usr/local/include)

include(FetchContent)

# nlohmann/json
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# cpp-httplib
FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.15.3
)
FetchContent_MakeAvailable(cpp_httplib)

add_executable(fuseviz-daemon
    src/main.cpp
    src/bpf_loader.cpp
    src/enricher.cpp
    src/storage.cpp
    src/ws_broadcaster.cpp
    src/security_engine.cpp
)

target_include_directories(fuseviz-daemon PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/../ebpf
    ${SQLITE3_INC}
)
if(HAVE_LIBBPF)
    target_include_directories(fuseviz-daemon PRIVATE ${LIBBPF_INC})
endif()

target_link_libraries(fuseviz-daemon PRIVATE
    Threads::Threads
    ${SQLITE3_LIB}
    nlohmann_json::nlohmann_json
    httplib::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
    z
)
if(HAVE_LIBBPF)
    target_link_libraries(fuseviz-daemon PRIVATE ${LIBBPF_LIB})
endif()

target_compile_options(fuseviz-daemon PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Release>:-flto>
)

install(TARGETS fuseviz-daemon DESTINATION bin)
