#!/usr/bin/env bash

BINARY_PATH="$1"
STLINK_SERIAL_NUMBER="$2"
# Get the directory where this script is located.
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" &> /dev/null && pwd)

if [ -z "$BINARY_PATH" ]; then
    echo "Libtropic NUCLEO U545RE-Q flash script"
    echo "usage: ./flash.sh PATH_TO_BINARY [STLINK_SERIAL_NUMBER]"
    exit 1
fi

if [ -z "$STLINK_SERIAL_NUMBER" ]; then
    echo "No STLink serial number provided, OpenOCD will autodiscover STLink programming interface."
    openocd -f "$SCRIPT_DIR/nucleo-u5xx.cfg" -c "program "$BINARY_PATH" verify reset exit"
else
    echo "Using STLink serial number: $STLINK_SERIAL_NUMBER"
    openocd -f "$SCRIPT_DIR/nucleo-u5xx.cfg" -c "adapter serial $STLINK_SERIAL_NUMBER" -c "program "$BINARY_PATH" verify reset exit"
fi