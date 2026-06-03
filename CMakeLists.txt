cmake_minimum_required(VERSION 3.16)
project(rhscanner VERSION 0.1.0 LANGUAGES CXX)

# ── Language standard ──────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Build type default ─────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ── Compiler warnings ──────────────────────────────────────────────────────────
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wno-unused-parameter   # stubs will have unused params until implemented
)

# Debug / Release flags
add_compile_options(
    $<$<CONFIG:Debug>:-g3>
    $<$<CONFIG:Debug>:-O0>
    $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    $<$<CONFIG:Release>:-O2>
)
add_link_options(
    $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)

# ── Source files ───────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    scanner/scanner.cpp
    service/service.cpp
    os/os.cpp
    threading/threading.cpp
    utils/utils.cpp
)

# ── Executable ─────────────────────────────────────────────────────────────────
add_executable(rhscanner ${SOURCES})

# ── Include paths ──────────────────────────────────────────────────────────────
target_include_directories(rhscanner PRIVATE ${CMAKE_SOURCE_DIR})

# ── Link libraries ─────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)
target_link_libraries(rhscanner PRIVATE Threads::Threads)

# ── Install ────────────────────────────────────────────────────────────────────
install(TARGETS rhscanner DESTINATION bin)

# ── Summary ────────────────────────────────────────────────────────────────────
message(STATUS "Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
