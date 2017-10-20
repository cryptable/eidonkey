
include( ${wxWidgets_USE_FILE} )

include_directories( .)
file(GLOB SOURCES *.cpp)

add_library(pindialogs STATIC ${SOURCES})

add_executable(pincode main.cpp)

target_link_libraries(pincode pindialogs ${wxWidgets_LIBRARIES})

install(TARGETS pincode RUNTIME DESTINATION $ENV{OUT_DIR}/../../..)