# Libtropic

![](https://github.com/tropicsquare/libtropic/actions/workflows/integration_tests.yml/badge.svg) ![](https://github.com/tropicsquare/libtropic/actions/workflows/build_docs_master.yml/badge.svg)

**Libtropic** is the official C SDK for TROPIC01, **the open and auditable secure element from Tropic Square**.

The repository provides the library and integration examples for practical evaluation of the chip. For information about particular TROPIC01 part number or for general insights into TROPIC01 design please follow link to [TROPIC01](https://github.com/tropicsquare/tropic01) product page.

## Getting started

If you are new to TROPIC01, start with the [model tutorial](https://tropicsquare.github.io/libtropic/latest/tutorials/model/) and use the chip emulator.
No physical chip is required, and all operations are reversible.

If you already have hardware, you might want to start with the platform tutorials:

- [STM32](https://tropicsquare.github.io/libtropic/latest/tutorials/)
- [ESP32](https://tropicsquare.github.io/libtropic/latest/tutorials/)
- [Linux](https://tropicsquare.github.io/libtropic/latest/tutorials/)

## Firmware compatibility

For correct operation, these four versions must be compatible:

1. **Libtropic SDK**: Version of this library.
2. **Bootloader FW**: Firmware running on TROPIC01 RISC-V CPU after power-up (cannot be updated).
3. **Application FW**: Firmware running on TROPIC01 RISC-V CPU (can be updated).
4. **SPECT FW**: Firmware running on the TROPIC01 SPECT co-processor (can be updated).

For details, see particular part number in [TROPIC01](https://github.com/tropicsquare/tropic01).

| Libtropic | Application FW | SPECT FW | Bootloader FW | Tests              |
|:---------:|:--------------:|:--------:|:-------------:|:------------------:|
| 1.0.0     | 1.0.0          | 1.0.0    | 1.0.1-2.0.1   | :white_check_mark: |
| 2.0.0     | 1.0.0–1.0.1    | 1.0.0    | 2.0.1         | :white_check_mark: |
| 2.0.1     | 1.0.0–1.0.1    | 1.0.0    | 2.0.1         | :white_check_mark: |
| 3.0.0     | 1.0.0–2.0.0    | 1.0.0    | 2.0.1         | :white_check_mark: |
| 3.1.0     | 1.0.0–2.0.0    | 1.0.0    | 2.0.1         | :white_check_mark: |

> [!WARNING]
> Mismatched component versions may cause errors or unpredictable behavior. Use the latest compatible versions whenever possible.

To read firmware versions and update firmware, use the [Tutorials](https://tropicsquare.github.io/libtropic/latest/tutorials/) and follow **Chip Identification** and **Firmware Update**.

## FAQ

See the [FAQ](https://tropicsquare.github.io/libtropic/latest/faq/) for common questions and troubleshooting.

## License

See [LICENSE.md](LICENSE.md) in the repository root, or check the [Tropic Square website](https://tropicsquare.com/license).



