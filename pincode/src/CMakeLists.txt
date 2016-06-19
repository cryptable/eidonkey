
include(${wxWidgets_USE_FILE})

include_directories( .)
file(GLOB SOURCES *.cpp)

add_library(pincode STATIC ${SOURCES})
target_link_libraries(pincode ${wxWidgets_LIBRARIES})

# install(TARGETS pincode LIBRARY DESTINATION $ENV{OUT_DIR})
install(TARGETS pincode ARCHIVE DESTINATION $ENV{OUT_DIR})