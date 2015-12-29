LINK_LIBRARIES(tins)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

ADD_EXECUTABLE(serialization-checker serialization-checker.cpp)
ADD_EXECUTABLE(packet-diff packet-diff.cpp)