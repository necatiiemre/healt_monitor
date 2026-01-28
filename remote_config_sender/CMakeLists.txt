cmake_minimum_required(VERSION 3.10)
project(remote_config_sender)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(remote_config_sender
    main.cpp
    ConfigSender.cpp
)
