
include( ${wxWidgets_USE_FILE} )

include_directories( .)
file(GLOB SOURCES *.cpp)

add_library(pincode STATIC ${SOURCES})

install(TARGETS pincode ARCHIVE DESTINATION $ENV{OUT_DIR}/../../..)