# 3. Hello, World! Example Tutorial

--8<-- "docs/common/examples_descriptions/hello_world.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/esp32/<your_board>/hello_world/
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

## Configuration
In addition to the [Libtropic CMake options](../../reference/integrating_libtropic/how_to_configure/index.md) used to configure Libtropic, this example provides the following CMake option:

- `LT_SH0_KEYS` (default: `"prod0"`) selects which pairing keys in slot 0 are used. Switch to engineering-sample pairing keys if your TROPIC01 is provisioned with them:

    ??? example "Switching to engineering sample pairing keys"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            idf.py -DLT_SH0_KEYS="eng_sample" build flash monitor
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA
    Additionally, see [Default Pairing Keys for a Secure Channel Handshake](../../reference/default_pairing_keys.md) for more information.