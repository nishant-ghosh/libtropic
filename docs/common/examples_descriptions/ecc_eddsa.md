This example demonstrates ECC key generation and EdDSA signing on the TROPIC01.
In this example, you will learn about the following functions:

- `lt_init()`: function used to initialize context for communication with the TROPIC01,
- `lt_verify_chip_and_start_secure_session()`: helper function to start Secure Session and allow L3 communication,
- `lt_ecc_key_erase()`: L3 command to erase an ECC key slot,
- `lt_ecc_key_generate()`: L3 command to generate an ECC key pair on the chip,
- `lt_ecc_key_read()`: L3 command to read the public key from an ECC key slot,
- `lt_ecc_eddsa_sign()`: L3 command to sign a message using EdDSA,
- `lt_session_abort()`: L3 command to abort Secure Session,
- `lt_deinit()`: function used to deinitialize context.
