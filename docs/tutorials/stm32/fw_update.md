# 2. FW Update Example Tutorial

--8<-- "docs/common/examples_descriptions/fw_update.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/stm32/<your_board>/fw_update/
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

    After successful execution, your chip will contain the latest firmware and will be compatible with the current Libtropic API.

!!! question "What if firmware update failed?"
    Check out the dedicated section in [FAQ](../../faq.md#fw-update-failed).

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

- `LT_SH0_KEYS` (default: `"prod0"`) to choose which pairing keys in slot 0 will be used. Switch to engineering sample pairing keys if your TROPIC01 has them:

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

- `LT_DISABLE_MAINTENANCE_MODE` (default: `"ON"`) to configure whether Maintenance Mode will be enabled/disabled. Set to `"OFF"` or `0` if your TROPIC01 has Maintenance Mode enabled and you don't want the FW update example to disable it:

    ??? example "Keeping Maintenance Mode enabled after FW update"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            cmake -DLT_DISABLE_MAINTENANCE_MODE=0 ..
            make
            make flash
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA

        !!! warning "Not recommended"
            This step is not recommended because it can increase the attack surface.

[Next example :material-arrow-right:](hello_world.md){ .md-button }