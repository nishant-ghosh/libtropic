# 4. ECC Key Generation and EdDSA Signing Example Tutorial

--8<-- "docs/common/examples_descriptions/ecc_eddsa.md"

!!! warning "This example erases ECC slot 0"
    This example erases any existing key in ECC slot 0 at the beginning and at the end of execution. If you have a key stored in slot 0 that you need, back it up or use a different slot before running this example.

## Build and Run
!!! example "Building and running the example"
    === ":fontawesome-brands-linux: Linux"
        Go to the example's project directory:
        ```bash { .copy }
        cd examples/linux/usb_devkit/ecc_eddsa/
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
        ./libtropic_ecc_eddsa
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

    After this, you should see an output in your terminal.

## Configuration
In addition to the [Libtropic CMake options](../../../reference/integrating_libtropic/how_to_configure/index.md) used to configure Libtropic, this example provides the following CMake options:

- `LT_USB_DEVKIT_PATH` (default: `"/dev/ttyACM0"`) sets the path to the USB device representing the USB DevKit serial port:

    ??? example "Configuring USB DevKit serial port"
        === ":fontawesome-brands-linux: Linux"
            ```bash { .copy }
            cmake -DLT_USB_DEVKIT_PATH=<serial_port_path> ..
            make
            ./libtropic_ecc_eddsa
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
            ./libtropic_ecc_eddsa
            ```

        === ":fontawesome-brands-apple: macOS"
            TBA

        === ":fontawesome-brands-windows: Windows"
            TBA
    Additionally, see [Default Pairing Keys for a Secure Channel Handshake](../../../reference/default_pairing_keys.md) for more information.

[Next example :material-arrow-right:](full_chain_verification.md){ .md-button }
