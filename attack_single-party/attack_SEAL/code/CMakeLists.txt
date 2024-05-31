# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEAL_attack VERSION 4.1 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_EXAMPLES)
    set(SEAL_BUILD_EXAMPLES ON)

    # Import Microsoft SEAL
    find_package(SEAL 4.1 REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_EXAMPLES)
    add_executable(attack_bgv_exe)
    add_executable(attack_bfv_exe)
    
    target_sources(attack_bgv_exe
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/src/cpad_attack_bgv.cpp
            ${CMAKE_CURRENT_LIST_DIR}/src/print_functions.cpp
            ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
    )
    target_sources(attack_bfv_exe
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/src/cpad_attack_bfv.cpp
            ${CMAKE_CURRENT_LIST_DIR}/src/print_functions.cpp
            ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(attack_bfv_exe PRIVATE SEAL::seal m)
        target_link_libraries(attack_bgv_exe PRIVATE SEAL::seal m)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(attack_bfv_exe PRIVATE SEAL::seal_shared m)
        target_link_libraries(attack_bgv_exe PRIVATE SEAL::seal_shared m)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()

