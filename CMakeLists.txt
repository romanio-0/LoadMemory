cmake_minimum_required(VERSION 3.26)
project(LoadMemory C)

set(CMAKE_C_STANDARD 11)

set(MAIN LoadMemory.c
        testMain.c)

add_executable(LoadMemory ${MAIN})

#add_definitions(-D UNICODE)