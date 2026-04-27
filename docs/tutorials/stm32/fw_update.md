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

    After this, you should see a colored output in your serial monitor.

If your TROPIC01 has engineering sample pairing keys, you can switch to them using the `LT_SH0_KEYS` CMake option:
!!! example "Switching to engineering sample pairing keys"
    === ":fontawesome-brands-linux: Linux"
        You can pass `LT_SH0_KEYS` to `cmake` as follows:
        ```bash { .copy }
        cmake -DLT_SH0_KEYS="eng_sample" ..
        make
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

Additionally, see [Default Pairing Keys for a Secure Channel Handshake](../../reference/default_pairing_keys.md) for more information.

If your TROPIC01 has Maintenance Mode enabled and you don't want the FW update example to disable it, use the `LT_DISABLE_MAINTENANCE_MODE` CMake option:
!!! example "Keeping Maintenance Mode enabled after FW update"
    === ":fontawesome-brands-linux: Linux"
        You can pass `LT_DISABLE_MAINTENANCE_MODE` to `cmake` as follows:
        ```bash { .copy }
        cmake -DLT_DISABLE_MAINTENANCE_MODE=0 ..
        make
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

    !!! warning "Not recommended"
        This step is not recommended because it can increase the attack surface.

!!! failure "FW update failed"
    Check out the dedicated section in [FAQ](../../faq.md#fw-update-failed).

[Next example :material-arrow-right:](hello_world.md){ .md-button }