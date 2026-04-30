/**
 * @file main.c
 * @brief Example showing how to perform an update of the TROPIC01 firmware using Libtropic and
 * ESP32-DevKitC-V4.
 * @copyright Copyright (c) 2020-2026 Tropic Square s.r.o.
 *
 * @license For the license see LICENSE.md in the root directory of this source tree.
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "fw_CPU.h"
#include "fw_SPECT.h"
#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_esp_idf.h"
#include "psa/crypto.h"

#define TAG "fw_update"

// Choose pairing keypair for slot 0.
#if LT_USE_SH0_ENG_SAMPLE
#define LT_EX_SH0_PRIV lt_sh0priv_eng_sample
#define LT_EX_SH0_PUB lt_sh0pub_eng_sample
#elif LT_USE_SH0_PROD0
#define LT_EX_SH0_PRIV lt_sh0priv_prod0
#define LT_EX_SH0_PUB lt_sh0pub_prod0
#endif

#if LT_DISABLE_MAINTENANCE_MODE
// Tracks whether the Maintenance Mode had to be enabled before starting the FW update.
bool g_maintenance_mode_was_enabled = false;

lt_ret_t check_and_enable_maintenance_mode(lt_handle_t *lt_handle)
{
    lt_ret_t ret;

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Checking if Maintenance Mode is enabled and enabling it in R-Config if needed:");

    // Establish Secure Channel Session so we can read I-Config/R-Config.
    ESP_LOGI(TAG, "  - Starting Secure Session with key slot %d...",
             (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    // Keys are chosen based on the CMake option LT_SH0_KEYS.
    ret = lt_verify_chip_and_start_secure_session(lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (LT_OK != ret) {
        ESP_LOGE(TAG, "Failed to start Secure Session with key %d, ret=%s",
                 (int)TR01_PAIRING_KEY_SLOT_INDEX_0, lt_ret_verbose(ret));
        ESP_LOGE(TAG,
                 "Check if you use correct SH0 keys! Hint: if you use an engineering sample chip, "
                 "compile with -DLT_SH0_KEYS=eng_sample");
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    // Read I-Config and check if Maintenance Mode is enabled.
    uint32_t i_config_cfg_startup;
    ESP_LOGI(TAG, "  - Reading I-Config[CFG_START_UP]...");
    ret = lt_i_config_read(lt_handle, TR01_CFG_START_UP_ADDR, &i_config_cfg_startup);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Failed to read I-Config[CFG_START_UP], ret=%s", lt_ret_verbose(ret));
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    ESP_LOGI(TAG, "  - Checking if Maintenance Mode is enabled in I-Config[CFG_START_UP]...");
    if (!(i_config_cfg_startup & BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK)) {
        ESP_LOGE(TAG, "Maintenance Mode is not enabled in I-Config -> FW Update cannot be performed.");
        return LT_FAIL;
    }
    ESP_LOGI(TAG, "  OK");

    // Read R-Config and check if Maintenance Mode is enabled.
    // The whole R-Config is read in case we need to modify it, as it has to be completely erased
    // before writing again.
    lt_config_t r_config;
    ESP_LOGI(TAG, "  - Reading R-Config...");
    ret = lt_read_whole_R_config(lt_handle, &r_config);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Failed to read R-Config, ret=%s", lt_ret_verbose(ret));
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    ESP_LOGI(TAG, "  - Read R-Config (acts as a backup):");
    for (int i = 0; i < LT_CONFIG_OBJ_CNT; i++) {
        ESP_LOGI(TAG, "    - %s= 0x%08" PRIx32, cfg_desc_table[i].desc, r_config.obj[i]);
    }

    ESP_LOGI(TAG, "  - Checking if Maintenance Mode is enabled in R-Config[CFG_START_UP]...");
    if (!(r_config.obj[TR01_CFG_START_UP_IDX] & BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK)) {
        ESP_LOGI(TAG, "Disabled, will enable it");
        ESP_LOGI(TAG, "    - Erasing R-Config...");
        ret = lt_r_config_erase(lt_handle);
        if (ret != LT_OK) {
            ESP_LOGE(TAG, "Failed to erase R-Config, ret=%s", lt_ret_verbose(ret));
            return ret;
        }
        ESP_LOGI(TAG, "    OK");

        r_config.obj[TR01_CFG_START_UP_IDX] |= BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK;
        ESP_LOGI(TAG, "    - Writing modified R-Config...");
        ret = lt_write_whole_R_config(lt_handle, &r_config);
        if (ret != LT_OK) {
            ESP_LOGE(TAG, "Failed to write R-Config, ret=%s", lt_ret_verbose(ret));
            ESP_LOGW(
                TAG,
                "R-Config is left in an erased state - the state before erasing is printed above.");
            return ret;
        }
        ESP_LOGI(TAG, "    OK");
        g_maintenance_mode_was_enabled = true;

        ESP_LOGI(TAG, "    - Rebooting TROPIC01 to apply R-Config changes...");
        ret = lt_reboot(lt_handle, TR01_REBOOT);
        if (ret != LT_OK) {
            ESP_LOGE(TAG, "lt_reboot() failed, ret=%s", lt_ret_verbose(ret));
            ESP_LOGW(TAG,
                     "R-Config (with Maintenance Mode enabled) was written but not applied yet. It "
                     "will be applied on next TROPIC01 reboot/power-cycle.");
            return ret;
        }
        ESP_LOGI(TAG, "    OK");
    }
    else {
        ESP_LOGI(TAG, "  OK");
    }

    return LT_OK;
}

lt_ret_t disable_maintenance_mode(lt_handle_t *lt_handle)
{
    lt_ret_t ret;

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Disabling Maintenance Mode in R-Config (reduces the attack surface):");

    ESP_LOGI(TAG, "  - Starting Secure Session with key slot %d...",
             (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    // Keys are chosen based on the CMake option LT_SH0_KEYS.
    ret = lt_verify_chip_and_start_secure_session(lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (LT_OK != ret) {
        ESP_LOGE(TAG, "Failed to start Secure Session with key %d, ret=%s",
                 (int)TR01_PAIRING_KEY_SLOT_INDEX_0, lt_ret_verbose(ret));
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    lt_config_t r_config;
    ESP_LOGI(TAG, "  - Reading R-Config...");
    ret = lt_read_whole_R_config(lt_handle, &r_config);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Failed to read R-Config, ret=%s", lt_ret_verbose(ret));
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    ESP_LOGI(TAG, "  - Erasing R-Config...");
    ret = lt_r_config_erase(lt_handle);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Failed to erase R-Config, ret=%s", lt_ret_verbose(ret));
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    ESP_LOGI(TAG, "  - Disabling Maintenance Mode in R-Config...");
    r_config.obj[TR01_CFG_START_UP_IDX] &= ~BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK;
    ret = lt_write_whole_R_config(lt_handle, &r_config);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Failed to write R-Config, ret=%s", lt_ret_verbose(ret));
        ESP_LOGW(TAG,
                 "R-Config is left in an erased state - the state before erasing is printed above.");
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    ESP_LOGI(TAG, "  - Rebooting TROPIC01 to apply R-Config changes...");
    ret = lt_reboot(lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "lt_reboot() failed, ret=%s", lt_ret_verbose(ret));
        ESP_LOGW(TAG,
                 "R-Config (with Maintenance Mode disabled) was written but not applied yet. It will "
                 "be applied on next TROPIC01 reboot/power-cycle.");
        return ret;
    }
    ESP_LOGI(TAG, "  OK");

    ESP_LOGI(TAG, "  - Verifying that Maintenance Mode is not accessible...");
    ret = lt_reboot(lt_handle, TR01_MAINTENANCE_REBOOT);
    if (ret == LT_L2_RESP_DISABLED) {
        ESP_LOGI(TAG, "  OK");
    }
    else if (ret != LT_OK) {
        ESP_LOGE(TAG, "lt_reboot() failed, ret=%s", lt_ret_verbose(ret));
        return ret;
    }
    else {
        ESP_LOGE(TAG, "Maintenance reboot succeeded! ret=%s", lt_ret_verbose(ret));
        return ret;
    }

    return LT_OK;
}
#endif

lt_ret_t get_fw_versions(lt_handle_t *lt_handle)
{
    uint8_t cpu_fw_ver[TR01_L2_GET_INFO_RISCV_FW_SIZE] = {0};
    uint8_t spect_fw_ver[TR01_L2_GET_INFO_SPECT_FW_SIZE] = {0};

    ESP_LOGI(TAG, "Reading firmware versions from TROPIC01...");
    lt_ret_t ret = lt_get_info_riscv_fw_ver(lt_handle, cpu_fw_ver);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Failed to get RISC-V FW version, ret=%s", lt_ret_verbose(ret));
        return ret;
    }
    ret = lt_get_info_spect_fw_ver(lt_handle, spect_fw_ver);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Failed to get SPECT FW version, ret=%s", lt_ret_verbose(ret));
        return ret;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "TROPIC01 firmware versions:");
    ESP_LOGI(TAG, "  - RISC-V FW version: %d.%d.%d", cpu_fw_ver[3], cpu_fw_ver[2], cpu_fw_ver[1]);
    ESP_LOGI(TAG, "  - SPECT FW version: %d.%d.%d", spect_fw_ver[3], spect_fw_ver[2], spect_fw_ver[1]);

    return LT_OK;
}

void app_main(void)
{
    ESP_LOGI(TAG, "==========================================");
    ESP_LOGI(TAG, "==== TROPIC01 Firmware Update Example ====");
    ESP_LOGI(TAG, "==========================================");

    // Cryptographic function provider initialization.
    //
    // In production, this would typically be done only once,
    // usually at the start of the application or before
    // the first use of cryptographic functions but no later than
    // the first occurrence of any Libtropic function
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA Crypto initialization failed, status=%d (psa_status_t)", status);
        return;
    }

    // Libtropic handle.
    //
    // It is declared here (on stack) for
    // simplicity. In production, you put it on heap if needed.
    lt_handle_t lt_handle = {0};

    // Device structure.
    //
    // Used default pins for a typical ESP32 DevKit; adjust if you use different wiring.
    lt_dev_esp_idf_t device = {0};
    device.spi_host_id = VSPI_HOST;
    device.spi_cs_gpio_pin = GPIO_NUM_5;
    device.spi_miso_pin = GPIO_NUM_19;
    device.spi_mosi_pin = GPIO_NUM_23;
    device.spi_clk_pin = GPIO_NUM_18;
    device.spi_clk_hz = 5000000; /* 5 MHz */
#if LT_USE_INT_PIN
    device.int_gpio_pin = GPIO_NUM_32;
#endif
    lt_handle.l2.device = &device;

#if LT_USE_INT_PIN
    // This function has to be called only once.
    // The call is needed because the Libtropic ESP-IDF HAL uses GPIO interrupts.
    esp_err_t esp_ret = gpio_install_isr_service(0);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "gpio_install_isr_service() failed: %s", esp_err_to_name(esp_ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }
#endif

    // Crypto abstraction layer (CAL) context.
    lt_ctx_mbedtls_v4_t crypto_ctx;
    lt_handle.l3.crypto_ctx = &crypto_ctx;

    ESP_LOGI(TAG, "Initializing handle...");
    lt_ret_t ret = lt_init(&lt_handle);
    if (LT_OK != ret) {
        ESP_LOGE(TAG, "Failed to initialize handle, ret=%s", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }
    ESP_LOGI(TAG, "OK");

    // First, we check versions of both updateable firmwares. To do that, we need TROPIC01 to **not**
    // be in the Start-up Mode. If there are valid firmwares, TROPIC01 will begin to execute them
    // automatically on boot.
    ESP_LOGI(TAG, "Rebooting TROPIC01...");
    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "Reboot failed, ret=%s", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }
    ESP_LOGI(TAG, "OK");

    if (get_fw_versions(&lt_handle) != LT_OK) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }

    ESP_LOGI(TAG, "Versions to update to:");
    ESP_LOGI(TAG, "  - RISC-V FW version: %d.%d.%d", fw_CPU_ver[3], fw_CPU_ver[2], fw_CPU_ver[1]);
    ESP_LOGI(TAG, "  - SPECT FW version: %d.%d.%d", fw_SPECT_ver[3], fw_SPECT_ver[2], fw_SPECT_ver[1]);

#if LT_DISABLE_MAINTENANCE_MODE
    // We need to make sure we can reboot into Maintenance Mode to perform the FW update.
    if (LT_OK != check_and_enable_maintenance_mode(&lt_handle)) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }
#endif

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Updating TROPIC01 firmware...");
    // This helper function implements the recommended FW update process.
    ret = lt_do_mutable_fw_update(&lt_handle, fw_CPU, sizeof(fw_CPU), fw_SPECT, sizeof(fw_SPECT));
    if (ret != LT_OK) {
        ESP_LOGE(TAG, "lt_do_mutable_fw_update() failed, ret=%s", lt_ret_verbose(ret));
        ESP_LOGE(TAG, "Tip: turn logging on to see more information (compile with -DLT_LOG_LVL=Info)");
#if LT_DISABLE_MAINTENANCE_MODE
        if (g_maintenance_mode_was_enabled) {
            ESP_LOGW(TAG, "Due to the error, Maintenance Mode was kept enabled in R-Config!");
        }
#endif
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }
    ESP_LOGI(TAG, "OK");

    if (get_fw_versions(&lt_handle) != LT_OK) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }

#if LT_DISABLE_MAINTENANCE_MODE
    // Warning: User shall disable Maintenance Mode only after both FW banks are updated with the
    // latest FW. If only one bank is updated (while the second one contains invalid FW), and
    // Maintenance Mode is disabled, the probability of bricking TROPIC01 increases. In this case, if
    // lt_do_mutable_fw_update() succeeds, it is safe to disable Maintenance Mode.
    if (LT_OK != disable_maintenance_mode(&lt_handle)) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return;
    }
#else
    ESP_LOGI(TAG, "");
    ESP_LOGW(
        TAG,
        "We strongly recommend disabling Maintenance Mode in R-Config to reduce the attack surface.");
#endif

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Deinitializing handle...");
    ret = lt_deinit(&lt_handle);
    if (LT_OK != ret) {
        ESP_LOGE(TAG, "Failed to deinitialize handle, ret=%s", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return;
    }
    ESP_LOGI(TAG, "OK");

    // Cryptographic function provider deinitialization.
    //
    // In production, this would be done only once, typically
    // during termination of the application.
    mbedtls_psa_crypto_free();
}
