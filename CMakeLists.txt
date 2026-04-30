# Top-level build for the LNK fuzzing campaign.
#
# Three executables come out of here:
#
#   lnk_fuzzer.exe       — the custom Jackalope frontend. Wires our LNKPRNG and LNKMutator into
#                          Jackalope's worker loop. This is what you actually run.
#   harness.exe          — fuzz target for shell32.dll (full IShellLinkW surface). Driven by
#                          lnk_fuzzer.exe over the SHM channel.
#   harness_darwin.exe   — fuzz target for msi.dll (advertised-shortcut / Darwin descriptor).
#                          Run as a separate campaign with its own seed corpus and a Darwin-biased
#                          scheduler weight.
#
# Jackalope is vendored under Jackalope/. We do NOT modify Jackalope/CMakeLists.txt — that's
# upstream and we want to be able to pull updates without merge pain. Instead, we add_subdirectory()
# it here and consume its `fuzzerlib` target.
#
# Build (Windows, from this directory):
#   cmake -S . -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#
# After building:
#   build\Release\lnk_fuzzer.exe -in seeds -out findings -t 5000 -delivery shmem -instrument_module shell32.dll -- build\Release\harness.exe -m @shm_id
#   build\Release\lnk_fuzzer.exe -in seeds_darwin -out findings_darwin -t 5000 -delivery shmem -instrument_module msi.dll -- build\Release\harness_darwin.exe -m @shm_id

cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(lnk_fuzzer LANGUAGES C CXX)

# Bring in Jackalope's fuzzerlib + tinyinst. This pulls Jackalope's own targets (fuzzer, test,
# fuzzerlib, tinyinst, plus its examples/) into the build. We only depend on `fuzzerlib`.
add_subdirectory(Jackalope)

# lnk_fuzzer_main.cc and lnk_mutator.cc include Jackalope headers by bare name
# (#include "fuzzer.h" etc — see the comment at the top of those files matching .clangd).
# Make Jackalope's source dir visible at compile time so those resolve.
set(JACKALOPE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Jackalope)

# ---------------------------------------------------------------------------------------------
# C core: format-aware mutator, scheduler, (de)serializer, model, PRNG.
# Used by lnk_fuzzer.exe (and by the offline `make test` build via the Makefile — that path
# uses cc directly and ignores this CMake file).
# ---------------------------------------------------------------------------------------------
set(LNK_CORE_SOURCES
    mutate.c
    serialize.c
    deserialize.c
    gen.c
    lnk_prng.c
)

set(LNK_CORE_HEADERS
    model.h
    mutate.h
    lnk_prng.h
    clsids.h
)

# ---------------------------------------------------------------------------------------------
# lnk_fuzzer.exe — the custom Jackalope frontend.
# ---------------------------------------------------------------------------------------------
add_executable(lnk_fuzzer
    lnk_fuzzer_main.cc
    lnk_mutator.cc
    lnk_prng_jackalope.cc
    lnk_prng_jackalope.h
    ${LNK_CORE_SOURCES}
    ${LNK_CORE_HEADERS}
)

target_include_directories(lnk_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${JACKALOPE_INCLUDE_DIR}
)

target_link_libraries(lnk_fuzzer PRIVATE fuzzerlib)

# ---------------------------------------------------------------------------------------------
# harness.exe — shell32.dll fuzz target.
# Pure Win32 + COM. No Jackalope link; it talks to the fuzzer over the SHM channel only.
# ---------------------------------------------------------------------------------------------
if(WIN32)
    add_executable(harness harness.cpp)
    target_link_libraries(harness PRIVATE ole32 shell32 propsys oleaut32)
    # /GS, /sdl etc. are MSVC defaults at Release. We don't disable them — fuzzer perf is
    # gated by shell32 anyway, and turning them off would mask real CFG-detected corruption.
endif()

# ---------------------------------------------------------------------------------------------
# harness_darwin.exe — msi.dll fuzz target.
# CommandLineFromMsiDescriptor is forward-declared in the source because it's missing from
# some Windows SDK msi.h headers; msi.lib still resolves it at link time.
# ---------------------------------------------------------------------------------------------
if(WIN32)
    add_executable(harness_darwin harness_darwin.cpp)
    target_link_libraries(harness_darwin PRIVATE msi ole32 shell32)
endif()
