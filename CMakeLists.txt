CMAKE_MINIMUM_REQUIRED(VERSION 2.8.1)
PROJECT(libtins-sanitizers)

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

FIND_PACKAGE(libtins)

ADD_SUBDIRECTORY(src)