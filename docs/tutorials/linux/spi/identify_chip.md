# 1. Chip Identification Example Tutorial

--8<-- "docs/common/examples_descriptions/identify_chip.md"

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/linux/spi/identify_chip/
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
        ./libtropic_identify_chip
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
            ./libtropic_identify_chip
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
            ./libtropic_identify_chip
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA

[Next example :material-arrow-right:](fw_update.md){ .md-button }