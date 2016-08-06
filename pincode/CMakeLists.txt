cmake_minimum_required(VERSION 2.8)
project(TEST)

find_package(wxWidgets REQUIRED core)

add_subdirectory(src)
add_subdirectory(test)

enable_testing()

add_test(NAME MyPINCodeTests COMMAND Test)

include(${wxWidgets_USE_FILE})