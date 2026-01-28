cmake_minimum_required(VERSION 3.10)

project(mainSoftware
    VERSION 1.0.0
    LANGUAGES CXX
)

# C++ standardi
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include dizini
include_directories(${CMAKE_SOURCE_DIR}/include)

# Kaynak dosyalari
set(SOURCES
    src/main.cpp
    src/UnitManager.cpp
    src/DeviceManager.cpp
    src/TdkLambdaPsu.cpp
    src/Dtn.cpp
    src/Hsn.cpp
    src/Cmc.cpp
    src/Mmc.cpp
    src/Vmc.cpp
    src/Utils.cpp
    src/SerialPort.cpp
    src/SystemCommand.cpp
    src/Server.cpp
    src/SSHDeployer.cpp
    src/CumulusHelper.cpp
    src/SerialTimeForwarder.cpp
)

# Executable olustur
add_executable(${PROJECT_NAME} ${SOURCES})

# Build dizini icin output ayari
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Proje kok dizinini compile-time'da tanimla (LOGS vs. icin)
target_compile_definitions(${PROJECT_NAME} PRIVATE
    PROJECT_ROOT="${CMAKE_SOURCE_DIR}"
)