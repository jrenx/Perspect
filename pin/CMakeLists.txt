cmake_minimum_required(VERSION 3.5)
project(pin)

set(CMAKE_CXX_STANDARD 14)

add_executable(python_test
        python_test.cpp)

find_package(PythonLibs REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})
target_link_libraries(python_test ${PYTHON_LIBRARIES})

