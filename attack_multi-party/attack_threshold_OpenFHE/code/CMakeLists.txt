cmake_minimum_required(VERSION 3.5.1)

# Set the project name
project(cpad_attack_threshold_openfhe CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)

# Set the build directory
set(CMAKE_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build)

# Set the output directory for the executable
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

# Option to include static versions of the library
option(BUILD_STATIC "Set to ON to include static versions of the library" OFF)

# Find OpenFHE package
find_package(OpenFHE CONFIG REQUIRED)
if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif()

# Set the C++ flags
set(CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS})

# Include directories
include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)

# Link directories
link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})

# Link libraries
if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries(${OpenFHE_STATIC_LIBRARIES})
else()
    set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
    link_libraries(${OpenFHE_SHARED_LIBRARIES})
endif()

# Define the executable target
add_executable(bfv_threshold_attack_exe
    ${CMAKE_CURRENT_LIST_DIR}/src/bfv_threshold_cpad_attack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/print_functions.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
)

