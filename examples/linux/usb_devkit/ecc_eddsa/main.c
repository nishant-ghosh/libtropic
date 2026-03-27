/**
 * @file main.c
 * @brief Example of ECC key generation and EdDSA signing using Libtropic with the USB DevKit.
 * @copyright Copyright (c) 2020-2026 Tropic Square s.r.o.
 *
 * @license For the license see LICENSE.md in the root directory of this source tree.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_posix_usb_devkit.h"
#include "psa/crypto.h"

// Choose pairing keypair for slot 0.
#if LT_USE_SH0_ENG_SAMPLE
#define LT_EX_SH0_PRIV sh0priv_eng_sample
#define LT_EX_SH0_PUB sh0pub_eng_sample
#elif LT_USE_SH0_PROD0
#define LT_EX_SH0_PRIV sh0priv_prod0
#define LT_EX_SH0_PUB sh0pub_prod0
#endif

// Message to sign with EdDSA.
#define SIGN_MSG "hello tropic"
#define SIGN_MSG_SIZE 12

int main(void)
{
    // Cosmetics: Disable buffering to keep output in order. You do not need to do this in your app if
    // you don't care about stdout/stderr output being shuffled or you use stdout only (or different
    // output mechanism altogether).
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("===========================================\n");
    printf("==== TROPIC01 ECC + EdDSA Sign Example ====\n");
    printf("===========================================\n");

    // Cryptographic function provider initialization.
    //
    // In production, this would typically be done only once,
    // usually at the start of the application or before
    // the first use of cryptographic functions but no later than
    // the first occurrence of any Libtropic function
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "PSA Crypto initialization failed, status=%d (psa_status_t)\n", status);
        return -1;
    }

    // Libtropic handle.
    //
    // It is declared here (on stack) for
    // simplicity. In production, you put it on heap if needed.
    lt_handle_t lt_handle = {0};

    // Device structure.
    //
    // Modify this according to your environment. Default values
    // are compatible with RPi and our RPi shield.
    lt_dev_posix_usb_devkit_t device = {0};

    // LT_USB_DEVKIT_PATH is defined in CMakeLists.txt. Pass -DLT_USB_DEVKIT_PATH=<path>
    // to cmake if you want to change it.
    int dev_path_len = snprintf(device.dev_path, sizeof(device.dev_path), "%s", LT_USB_DEVKIT_PATH);
    if (dev_path_len < 0 || (size_t)dev_path_len >= sizeof(device.dev_path)) {
        fprintf(
            stderr,
            "Error: LT_USB_DEVKIT_PATH is too long for device.dev_path buffer (limit is %zu bytes).\n",
            sizeof(device.dev_path));
        mbedtls_psa_crypto_free();
        return -1;
    }

    device.baud_rate = 115200;
    lt_handle.l2.device = &device;

    // Crypto abstraction layer (CAL) context.
    lt_ctx_mbedtls_v4_t crypto_ctx;
    lt_handle.l3.crypto_ctx = &crypto_ctx;

    printf("Initializing handle...");
    lt_ret_t ret = lt_init(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to initialize handle, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // We need to ensure we are not in the Startup Mode, as L3 commands are available only in the
    // Application Firmware.
    printf("Sending reboot request...");
    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("Starting Secure Session with key slot %d...", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    // Keys are chosen based on the CMake option LT_SH0_KEYS.
    ret = lt_verify_chip_and_start_secure_session(&lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to start Secure Session with key %d, ret=%s\n",
                (int)TR01_PAIRING_KEY_SLOT_INDEX_0, lt_ret_verbose(ret));
        fprintf(stderr,
                "Check if you use correct SH0 keys! Hint: if you use an engineering sample chip, "
                "compile with "
                "-DLT_SH0_KEYS=eng_sample\n");
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Erase any existing key in slot 0 before generating a new one.
    printf("Erasing ECC slot 0...");
    ret = lt_ecc_key_erase(&lt_handle, TR01_ECC_SLOT_0);
    if (LT_OK != ret) {
        fprintf(stderr, "\nECC key erase failed, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Generate an ECC key pair on the chip (Ed25519, slot 0).
    printf("Generating ECC key (Ed25519, slot 0)...");
    ret = lt_ecc_key_generate(&lt_handle, TR01_ECC_SLOT_0, TR01_CURVE_ED25519);
    if (LT_OK != ret) {
        fprintf(stderr, "\nECC key generation failed, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Read back the public key.
    uint8_t pub_key[64];
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;
    printf("Reading ECC public key...");
    ret = lt_ecc_key_read(&lt_handle, TR01_ECC_SLOT_0, pub_key, sizeof(pub_key), &curve, &origin);
    if (LT_OK != ret) {
        fprintf(stderr, "\nECC key read failed, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("Public key: ");
    int key_len = (curve == TR01_CURVE_ED25519) ? 32 : 64;
    for (int i = 0; i < key_len; i++) {
        printf("%02x", pub_key[i]);
    }
    printf("\n");

    // EdDSA signature of the message.
    uint8_t rs[64];
    printf("Signing message '%s' with EdDSA...", SIGN_MSG);
    ret = lt_ecc_eddsa_sign(&lt_handle, TR01_ECC_SLOT_0, (const uint8_t *)SIGN_MSG, SIGN_MSG_SIZE, rs);
    if (LT_OK != ret) {
        fprintf(stderr, "\nEdDSA sign failed, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("Signature: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", rs[i]);
    }
    printf("\n");

    // Clean up: erase the key from slot 0 so we don't leave behind test data.
    printf("Erasing ECC slot 0...");
    ret = lt_ecc_key_erase(&lt_handle, TR01_ECC_SLOT_0);
    if (LT_OK != ret) {
        fprintf(stderr, "\nECC key erase failed, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("Aborting Secure Session...");
    ret = lt_session_abort(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to abort Secure Session, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("Deinitializing handle...");
    ret = lt_deinit(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to deinitialize handle, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Cryptographic function provider deinitialization.
    //
    // In production, this would be done only once, typically
    // during termination of the application.
    mbedtls_psa_crypto_free();

    return 0;
}
