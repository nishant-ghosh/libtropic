cmake_minimum_required(VERSION 3.21.0)

set(LT_HAL_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/libtropic_port_posix_usb_devkit.c
    # nanopb
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb/pb_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb/pb_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb/pb_decode.c
    # protobuf messages for new USB DevKit FW
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../examples/applications/tropic01_util/protobuf/generated/usb_devkit_messages.pb.c
)

set(LT_HAL_INC_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    # nanopb
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb/
    # protobuf messages for new USB DevKit FW
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../examples/applications/tropic01_util/protobuf/generated/
)

# export generic names for parent to consume
set(LT_HAL_SRCS ${LT_HAL_SRCS} PARENT_SCOPE)
set(LT_HAL_INC_DIRS ${LT_HAL_INC_DIRS} PARENT_SCOPE)