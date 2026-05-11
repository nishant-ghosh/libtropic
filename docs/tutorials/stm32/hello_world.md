# 3. Hello, World! Example Tutorial

--8<-- "docs/common/examples_descriptions/hello_world.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/stm32/<your_board>/hello_world/
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

    After this, you should see an output in your serial monitor.

## Configuration
In addition to the [Libtropic CMake options](../../reference/integrating_libtropic/how_to_configure/index.md) used to configure Libtropic, this example provides the following CMake options:

- `STLINK_SERIAL_NUMBER` (default: none, OpenOCD looks for any STLink programming interface) specifies the serial number of the STLink device used for flashing. This is needed only when you have multiple STM32s connected via built-in STLink or when OpenOCD autodetection does not work:

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

- `LT_SH0_KEYS` (default: `"prod0"`) selects which pairing keys in slot 0 are used. Switch to engineering-sample pairing keys if your TROPIC01 is provisioned with them:

    ??? example "Switching to engineering sample pairing keys"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            cmake -DLT_SH0_KEYS="eng_sample" ..
            make
            make flash
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA
    Additionally, see [Default Pairing Keys for a Secure Channel Handshake](../../reference/default_pairing_keys.md) for more information.