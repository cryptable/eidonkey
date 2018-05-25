
include( ${wxWidgets_USE_FILE} )

include_directories( .)
file(GLOB SOURCES *.cpp)

add_definitions(-DHAVE_TYPE_TRAITS)

add_library(pincode STATIC ${SOURCES})

install(TARGETS pincode ARCHIVE DESTINATION $ENV{OUT_DIR}/../../..)