# 1. Chip Identification Example Tutorial

--8<-- "docs/common/examples_descriptions/identify_chip.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/stm32/<your_board>/identify_chip/
        ```

        Create a `build/` directory and switch to it:
        ```bash { .copy }
        mkdir build/
        cd build/
        ```

        Open your STM32's serial port using your preferred serial monitor with configuration 8-N-1 and baudrate set to 115200. By default, the serial port is mapped to `/dev/ttyACM0`. For example, using GTKTerm:
        ```bash { .copy }
        gtkterm -p /dev/ttyACM0 -s 115200
        ```

        !!! warning
            Make sure only one serial monitor has the STM32's serial port open, otherwise your output may appear mangled.

        And finally, build and run the example:
        ```bash { .copy }
        cmake ..
        make
        make flash
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

    After this, you should see a colored output in your serial monitor.

## Configuration
Beside the [Libtropic CMake options](../../reference/integrating_libtropic/how_to_configure/index.md) used to configure Libtropic, there are multiple CMake options specific to this example:

- `STLINK_SERIAL_NUMBER` (default: none, OpenOCD looks for any STLink programming interface) to set the serial number of the STLink device which will be used for flashing. This is needed only when you have multiple STM32s connected using built-in STLink or problems with OpenOCD's autodetection:

    ??? example "Configuring STLink serial number"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            cmake -DSTLINK_SERIAL_NUMBER=<stlink_serial_number> ..
            make
            make flash
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA

[Next example :material-arrow-right:](fw_update.md){ .md-button }