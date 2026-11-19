cmake_minimum_required(VERSION 3.20)

# ── vcpkg auto-detection (Windows) ─────────────────────────────────────────
# If the user ran plain `cmake -B build` without -DCMAKE_TOOLCHAIN_FILE, but a
# vcpkg installation with libsodium already exists, wire it up automatically.
# Triplet preference matches the compiler we expect to end up with: MinGW GCC
# (see self-defense below) pairs with *-mingw-static; MSVC pairs with *-windows*.
if(WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE AND NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(_FA_VCPKG_ROOT "")
    if(DEFINED ENV{VCPKG_ROOT} AND EXISTS "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
        set(_FA_VCPKG_ROOT "$ENV{VCPKG_ROOT}")
    elseif(EXISTS "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(_FA_VCPKG_ROOT "C:/vcpkg")
    endif()
    if(_FA_VCPKG_ROOT)
        find_program(_FA_MINGW_GXX g++)
        set(_FA_TRIPLET_ORDER "x64-windows;x64-windows-static;x64-mingw-static")
        if(_FA_MINGW_GXX)
            set(_FA_TRIPLET_ORDER "x64-mingw-static;x64-windows;x64-windows-static")
        endif()
        foreach(_FA_TRIPLET IN LISTS _FA_TRIPLET_ORDER)
            if(EXISTS "${_FA_VCPKG_ROOT}/installed/${_FA_TRIPLET}/include/sodium.h")
                set(CMAKE_TOOLCHAIN_FILE "${_FA_VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "" FORCE)
                set(VCPKG_TARGET_TRIPLET "${_FA_TRIPLET}" CACHE STRING "" FORCE)
                message(STATUS "Auto-detected vcpkg libsodium: ${_FA_VCPKG_ROOT} (triplet ${_FA_TRIPLET})")
                break()
            endif()
        endforeach()
        unset(_FA_MINGW_GXX CACHE)
    endif()
endif()

# ── Compiler self-defense (Windows) ─────────────────────────────────────
# CMake's compiler search also tries `clang++`, and machines with a stale LLVM
# on PATH (older than the installed MSVC STL) die with fatal STL1000: "expected
# Clang 20 or newer". When the user hasn't chosen a compiler and a MinGW g++
# exists, prefer it — GCC builds this code cleanly (verified).
# Skipped when vcpkg selected an MSVC-ABI triplet above.
if(WIN32 AND NOT DEFINED CMAKE_CXX_COMPILER
        AND NOT VCPKG_TARGET_TRIPLET MATCHES "^x64-windows")
    find_program(_FA_GXX g++)
    if(_FA_GXX)
        set(CMAKE_CXX_COMPILER "${_FA_GXX}" CACHE FILEPATH "C++ compiler" FORCE)
    endif()
    unset(_FA_GXX CACHE)
endif()

project(frostauth-sdk-cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── libsodium ────────────────────────────────────────────────────────────
# Resolution order: vcpkg config (auto-wired above or passed explicitly) →
# system libsodium via pkg-config (Linux/macOS, mingw without vcpkg).
set(FROSTAUTH_SODIUM_TARGET "")
find_package(unofficial-sodium QUIET CONFIG)
if(unofficial-sodium_FOUND)
    set(FROSTAUTH_SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
        if(SODIUM_FOUND)
            set(FROSTAUTH_SODIUM_TARGET PkgConfig::SODIUM)
        endif()
    endif()
endif()
if(NOT FROSTAUTH_SODIUM_TARGET)
    message(FATAL_ERROR
        "libsodium was not found. Install it one of these ways:\n"
        "  Windows + vcpkg:  vcpkg install libsodium:x64-mingw-static   (or :x64-windows)\n"
        "                    then re-run cmake with -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake\n"
        "  Linux:            apt install libsodium-dev  (or pacman -S libsodium)\n"
        "  macOS:            brew install libsodium")
endif()

# ── SDK library ──────────────────────────────────────────────────────────────
add_library(frostauth STATIC frostauth.cpp)
target_include_directories(frostauth PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(frostauth PUBLIC ${FROSTAUTH_SODIUM_TARGET})

if(WIN32)
    target_link_libraries(frostauth PUBLIC winhttp ws2_32)
else()
    find_package(CURL REQUIRED)
    target_link_libraries(frostauth PUBLIC CURL::libcurl)
endif()

# ── console example ──────────────────────────────────────────────────────────
add_executable(frostauth-console examples/console_main.cpp)
target_link_libraries(frostauth-console PRIVATE frostauth)
