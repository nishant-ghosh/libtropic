# 3. Hello, World! Example Tutorial

--8<-- "docs/common/examples_descriptions/hello_world.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/linux/usb_devkit/hello_world/
        ```

        Create a `build/` directory and switch to it:
        ```bash { .copy }
        mkdir build/
        cd build/
        ```

        And finally, build and run the example:
        ```bash { .copy }
        cmake ..
        make
        ./libtropic_hello_world
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

    After this, you should see an output in your terminal.

## Configuration
Beside the [Libtropic CMake options](../../../reference/integrating_libtropic/how_to_configure/index.md) used to configure Libtropic, there are multiple CMake options specific to this example:

- `LT_USB_DEVKIT_PATH` (default: `"/dev/ttyACM0"`) to set the path to the USB device representing the USB DevKit serial port:

    ??? example "Configuring USB DevKit serial port"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            cmake -DLT_USB_DEVKIT_PATH=<serial_port_path> ..
            make
            ./libtropic_hello_world
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
            ./libtropic_hello_world
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA
    Additionally, see [Default Pairing Keys for a Secure Channel Handshake](../../../reference/default_pairing_keys.md) for more information.

[Next example :material-arrow-right:](ecc_eddsa.md){ .md-button }