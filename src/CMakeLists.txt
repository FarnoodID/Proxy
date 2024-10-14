#anounce minimum of cmake version to use
cmake_minimum_required(VERSION 3.0.0)

#sources that are at the same location as CMAKE FILE
FilE(GLOB SOURCES "*.cpp")

#included headers in ./include
include_directories(include)

#spdlog headers in spdlog/include
include_directories(spdlog/include)

#boost libraries included
find_package(Boost 1.65.1 COMPONENTS system thread REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

#make executable main
ADD_EXECUTABLE (main ${SOURCES})

#link boost libraries to executable file
TARGET_LINK_LIBRARIES(main LINK_PUBLIC ${Boost_LIBRARIES})
