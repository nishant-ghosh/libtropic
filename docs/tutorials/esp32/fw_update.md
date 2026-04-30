# 2. FW Update Example Tutorial

--8<-- "docs/common/examples_descriptions/fw_update.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/esp32/<your_board>/fw_update/
        ```

        Build, flash and run the serial monitor using this command:
        ```bash { .copy }
        idf.py build flash monitor
        ```
        After this, you should see a colored output in your terminal.

        !!! tip "Closing the ESP-IDF serial monitor"
            To close the ESP-IDF serial monitor, press <kbd>Ctrl</kbd> + <kbd>]</kbd>. Refer to the [ESP-IDF monitor documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/tools/idf-monitor.html) for a full list of available keyboard shortcuts.

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

If your TROPIC01 has engineering sample pairing keys, you can switch to them using the `LT_SH0_KEYS` CMake option:
!!! example "Switching to engineering sample pairing keys"
    === ":fontawesome-brands-linux: Linux"
        You can pass any CMake option to `idf.py` as follows:
        ```bash { .copy }
        idf.py -DLT_SH0_KEYS="eng_sample" build flash monitor
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

Additionally, see [Default Pairing Keys for a Secure Channel Handshake](../../reference/default_pairing_keys.md) for more information.

If your TROPIC01 has Maintenance Mode enabled and you don't want the FW update example to disable it, use the `LT_DISABLE_MAINTENANCE_MODE` CMake option:
!!! example "Keeping Maintenance Mode enabled after FW update"
    === ":fontawesome-brands-linux: Linux"
        You can pass any CMake option to `idf.py` as follows:
        ```bash { .copy }
        idf.py -DLT_DISABLE_MAINTENANCE_MODE=0 build flash monitor
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