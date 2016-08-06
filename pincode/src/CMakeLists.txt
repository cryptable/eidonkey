
include(${wxWidgets_USE_FILE})

include_directories( .)
file(GLOB SOURCES pincode.cpp PinCodeDlg.cpp PinCodeVal.cpp SignPinCodeDlg.cpp)

add_library(pindialogs ${SOURCES})

add_executable(pincode main.cpp)

target_link_libraries(pincode ${wxWidgets_LIBRARIES} pindialogs)