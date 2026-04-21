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

[Next example :material-arrow-right:](hello_world.md){ .md-button }