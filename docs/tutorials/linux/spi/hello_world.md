# 3. Hello, World! Example Tutorial

--8<-- "docs/common/examples_descriptions/hello_world.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/linux/spi/hello_world/
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
In addition to the [Libtropic CMake options](../../../reference/integrating_libtropic/how_to_configure/index.md) used to configure Libtropic, this example provides the following CMake options:

- `LT_SPI_DEV_PATH` (default: `"/dev/spidev0.0"`) specifies the path to the SPI device to which the TROPIC01 is connected:

    ??? example "Configuring SPI device path"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            cmake -DLT_SPI_DEV_PATH=<spi_dev_path> ..
            make
            ./libtropic_hello_world
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA

- `LT_GPIO_DEV_PATH` (default: `"/dev/gpiochip0"`) specifies the path to the GPIO device to which TROPIC01's interrupt (INT) and Chip Select (CS) lines are connected:

    ??? example "Configuring GPIO device path"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            cmake -DLT_GPIO_DEV_PATH=<gpio_dev_path> ..
            make
            ./libtropic_hello_world
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
            ./libtropic_hello_world
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA
    Additionally, see [Default Pairing Keys for a Secure Channel Handshake](../../../reference/default_pairing_keys.md) for more information.

[Next example :material-arrow-right:](full_chain_verification.md){ .md-button }