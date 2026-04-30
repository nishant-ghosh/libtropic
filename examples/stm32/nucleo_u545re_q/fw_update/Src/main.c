/**
 * @file main.c
 * @brief Example showing how to perform an update of the TROPIC01 firmware using Libtropic on STM32
 * Nucleo U545RE-Q board.
 * @copyright Copyright (c) 2020-2026 Tropic Square s.r.o.
 *
 * @license For the license see LICENSE.md in the root directory of this source tree.
 */

// This file was generated using Stm32CubeMX and modified by Tropic Square to run Libtropic
// functional tests.

/**
 * Copyright (c) 2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 */

/* Includes ------------------------------------------------------------------*/
#include "main.h"

#include <inttypes.h>
#include <stdio.h>

#include "fw_CPU.h"
#include "fw_SPECT.h"
#include "libtropic.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_stm32u5xx.h"
#include "psa/crypto.h"

/* Private define ------------------------------------------------------------*/

/* Choose pairing keypair for slot 0. */
#if LT_USE_SH0_ENG_SAMPLE
#define LT_EX_SH0_PRIV lt_sh0priv_eng_sample
#define LT_EX_SH0_PUB lt_sh0pub_eng_sample
#elif LT_USE_SH0_PROD0
#define LT_EX_SH0_PRIV lt_sh0priv_prod0
#define LT_EX_SH0_PUB lt_sh0pub_prod0
#endif

/* Private variables ---------------------------------------------------------*/
/* RNG handle declaration */
RNG_HandleTypeDef hrng;

#if LT_DISABLE_MAINTENANCE_MODE
/* Tracks whether the Maintenance Mode had to be enabled before starting the FW update. */
bool g_maintenance_mode_was_enabled = false;
#endif

/* UART handle declaration */
UART_HandleTypeDef huart1;

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void SystemPower_Config(void);
static void MX_GPIO_Init(void);
static void MX_ICACHE_Init(void);
static void MX_RNG_Init(void);
static void MX_USART1_UART_Init(void);

#if defined(__ICCARM__)
/* New definition from EWARM V9, compatible with EWARM8 */
int iar_fputc(int ch);
#define PUTCHAR_PROTOTYPE int iar_fputc(int ch)
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
/* ARM Compiler 5/6*/
#define PUTCHAR_PROTOTYPE int fputc(int ch, FILE *f)
#elif defined(__GNUC__)
#define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#endif /* __ICCARM__ */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

#if LT_DISABLE_MAINTENANCE_MODE
/**
 * @brief  Checks if Maintenance Mode is enabled and if not, enables it in R-Config.
 * @param  lt_handle_t Device handle
 * @retval LT_OK on success
 */
lt_ret_t check_and_enable_maintenance_mode(lt_handle_t *lt_handle)
{
    lt_ret_t ret;

    printf("\nChecking if Maintenance Mode is enabled and enabling it in R-Config if needed:\n");

    // Establish Secure Channel Session so we can read I-Config/R-Config.
    printf("  - Starting Secure Session with key slot %d...", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    // Keys are chosen based on the CMake option LT_SH0_KEYS.
    ret = lt_verify_chip_and_start_secure_session(lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to start Secure Session with key %d, ret=%s\n",
                (int)TR01_PAIRING_KEY_SLOT_INDEX_0, lt_ret_verbose(ret));
        fprintf(stderr,
                "Check if you use correct SH0 keys! Hint: if you use an engineering sample chip, "
                "compile with "
                "-DLT_SH0_KEYS=eng_sample\n");
        return ret;
    }
    printf("OK\n");

    // Read I-Config and check if Maintenance Mode is enabled.
    uint32_t i_config_cfg_startup;
    printf("  - Reading I-Config[CFG_START_UP]...");
    ret = lt_i_config_read(lt_handle, TR01_CFG_START_UP_ADDR, &i_config_cfg_startup);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to read I-Config[CFG_START_UP], ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    printf("OK\n");

    printf("  - Checking if Maintenance Mode is enabled in I-Config[CFG_START_UP]...");
    if (!(i_config_cfg_startup & BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK)) {
        fprintf(stderr,
                "\nMaintenance Mode is not enabled in I-Config -> FW Update cannot be performed.\n");
        return LT_FAIL;
    }
    printf("OK\n");

    // Read R-Config and check if Maintenance Mode is enabled.
    // The whole R-Config is read in case we need to modify it, as it has to be completely erased
    // before writing again.
    lt_config_t r_config;
    printf("  - Reading R-Config...");
    ret = lt_read_whole_R_config(lt_handle, &r_config);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to read R-Config, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    printf("OK\n");

    printf("  - Read R-Config (acts as a backup):\n");
    for (int i = 0; i < LT_CONFIG_OBJ_CNT; i++) {
        printf("    - %s= 0x%08" PRIx32 "\n", cfg_desc_table[i].desc, r_config.obj[i]);
    }

    printf("  - Checking if Maintenance Mode is enabled in R-Config[CFG_START_UP]...");
    if (!(r_config.obj[TR01_CFG_START_UP_IDX] & BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK)) {
        printf("Disabled, will enable it\n");
        printf("    - Erasing R-Config...");
        ret = lt_r_config_erase(lt_handle);
        if (ret != LT_OK) {
            fprintf(stderr, "\nFailed to erase R-Config, ret=%s\n", lt_ret_verbose(ret));
            return ret;
        }
        printf("OK\n");

        r_config.obj[TR01_CFG_START_UP_IDX] |= BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK;
        printf("    - Writing modified R-Config...");
        ret = lt_write_whole_R_config(lt_handle, &r_config);
        if (ret != LT_OK) {
            fprintf(stderr, "\nFailed to write R-Config, ret=%s\n", lt_ret_verbose(ret));
            fprintf(stderr,
                    "WARNING: R-Config is left in an erased state - the state before erasing is "
                    "printed above.\n");
            return ret;
        }
        printf("OK\n");
        g_maintenance_mode_was_enabled = true;

        printf("    - Rebooting TROPIC01 to apply R-Config changes...");
        ret = lt_reboot(lt_handle, TR01_REBOOT);
        if (ret != LT_OK) {
            fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
            fprintf(stderr,
                    "WARNING: R-Config (with Maintenance Mode enabled) was written but not applied "
                    "yet. It will be applied on next TROPIC01 reboot/power-cycle.\n");
            return ret;
        }
        printf("OK\n");
    }
    else {
        printf("OK\n");
    }

    return LT_OK;
}

/**
 * @brief  Disables Maintenance Mode.
 * @param  lt_handle_t Device handle
 * @retval LT_OK on success
 */
lt_ret_t disable_maintenance_mode(lt_handle_t *lt_handle)
{
    lt_ret_t ret;

    printf("\nDisabling Maintenance Mode in R-Config (reduces the attack surface):\n");

    printf("  - Starting Secure Session with key slot %d...", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    // Keys are chosen based on the CMake option LT_SH0_KEYS.
    ret = lt_verify_chip_and_start_secure_session(lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to start Secure Session with key %d, ret=%s\n",
                (int)TR01_PAIRING_KEY_SLOT_INDEX_0, lt_ret_verbose(ret));
        return ret;
    }
    printf("OK\n");

    lt_config_t r_config;
    printf("  - Reading R-Config...");
    ret = lt_read_whole_R_config(lt_handle, &r_config);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to read R-Config, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    printf("OK\n");

    printf("  - Erasing R-Config...");
    ret = lt_r_config_erase(lt_handle);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to erase R-Config, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    printf("OK\n");

    printf("  - Disabling Maintenance Mode in R-Config...");
    r_config.obj[TR01_CFG_START_UP_IDX] &= ~BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK;
    ret = lt_write_whole_R_config(lt_handle, &r_config);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to write R-Config, ret=%s\n", lt_ret_verbose(ret));
        fprintf(stderr,
                "WARNING: R-Config is left in an erased state - the state before erasing is printed "
                "above.\n");
        return ret;
    }
    printf("OK\n");

    printf("  - Rebooting TROPIC01 to apply R-Config changes...");
    ret = lt_reboot(lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        fprintf(stderr,
                "WARNING: R-Config (with Maintenance Mode disabled) was written but not applied yet. "
                "It will be applied on next TROPIC01 reboot/power-cycle.\n");
        return ret;
    }
    printf("OK\n");

    printf("  - Verifying that Maintenance Mode is not accessible...");
    ret = lt_reboot(lt_handle, TR01_MAINTENANCE_REBOOT);
    if (ret == LT_L2_RESP_DISABLED) {
        printf("OK\n");
    }
    else if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    else {
        fprintf(stderr, "\nMaintenance reboot succeeded! ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }

    return LT_OK;
}
#endif

/**
 * @brief  Retrieve and print versions of TROPIC01 firmware
 * @param  lt_handle_t Device handle
 * @retval LT_OK on success
 */
lt_ret_t get_fw_versions(lt_handle_t *lt_handle)
{
    uint8_t cpu_fw_ver[TR01_L2_GET_INFO_RISCV_FW_SIZE] = {0};
    uint8_t spect_fw_ver[TR01_L2_GET_INFO_SPECT_FW_SIZE] = {0};

    printf("Reading firmware versions from TROPIC01...");
    lt_ret_t ret = lt_get_info_riscv_fw_ver(lt_handle, cpu_fw_ver);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to get RISC-V FW version, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    ret = lt_get_info_spect_fw_ver(lt_handle, spect_fw_ver);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to get SPECT FW version, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    printf("OK\n");

    printf("TROPIC01 firmware versions:\n");
    printf("  - RISC-V FW version: %d.%d.%d\n", cpu_fw_ver[3], cpu_fw_ver[2], cpu_fw_ver[1]);
    printf("  - SPECT FW version: %d.%d.%d\n", spect_fw_ver[3], spect_fw_ver[2], spect_fw_ver[1]);

    return LT_OK;
}

/**
 * @brief  The application entry point.
 * @retval int
 */
int main(void)
{
    /* MCU Configuration--------------------------------------------------------*/

    /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
    HAL_Init();

    /* Configure the System Power */
    SystemPower_Config();

    /* Configure the system clock */
    SystemClock_Config();

    /* Initialize all configured peripherals */
    MX_GPIO_Init();
    MX_ICACHE_Init();
    MX_RNG_Init();
    MX_USART1_UART_Init();

    /* libtropic related code BEGIN */
    /* libtropic related code BEGIN */
    /* libtropic related code BEGIN */
    /* libtropic related code BEGIN */
    /* libtropic related code BEGIN */

    printf("==========================================\n");
    printf("==== TROPIC01 Firmware Update Example ====\n");
    printf("==========================================\n");

    /* Cryptographic function provider initialization.

        In production, this would typically be done only once,
        usually at the start of the application or before
        the first use of cryptographic functions but no later than
        the first occurrence of any Libtropic function */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "PSA Crypto initialization failed, status=%ld (psa_status_t)\n", status);
        return -1;
    }

    /* Libtropic handle.

        It is declared here (on stack) for
        simplicity. In production, you put it on heap if needed. */
    lt_handle_t lt_handle = {0};

    /* Device structure.

        Modify this according to your environment. Default values
        are compatible with RPi and our RPi shield.

        The device structure has to be zero initialized!
        STM32 HAL depends on zero init values. */
    lt_dev_stm32u5xx_t device = {0};

    device.spi_instance = SPI1;
    device.baudrate_prescaler = SPI_BAUDRATEPRESCALER_2;
    device.spi_cs_gpio_bank = GPIOC;
    device.spi_cs_gpio_pin = GPIO_PIN_9;
    device.rng_handle = &hrng;

#ifdef LT_USE_INT_PIN
    device.int_gpio_bank = GPIOC;
    device.int_gpio_pin = GPIO_PIN_8;
#endif

    lt_handle.l2.device = &device;

    /* Crypto abstraction layer (CAL) context. */
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

    /* First, we check versions of both updateable firmwares. To do that, we need TROPIC01 to **not**
       be in the Start-up Mode. If there are valid firmwares, TROPIC01 will begin to execute them
       automatically on boot. */
    printf("Rebooting TROPIC01...");
    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    if (get_fw_versions(&lt_handle) != LT_OK) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }

    printf("Versions to update to:\n");
    printf("  - RISC-V FW version: %d.%d.%d\n", fw_CPU_ver[3], fw_CPU_ver[2], fw_CPU_ver[1]);
    printf("  - SPECT FW version: %d.%d.%d\n", fw_SPECT_ver[3], fw_SPECT_ver[2], fw_SPECT_ver[1]);

#if LT_DISABLE_MAINTENANCE_MODE
    // We need to make sure we can reboot into Maintenance Mode to perform the FW update.
    if (LT_OK != check_and_enable_maintenance_mode(&lt_handle)) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
#endif

    printf("\nUpdating TROPIC01 firmware...");
    // This helper function implements the recommended FW update process.
    ret = lt_do_mutable_fw_update(&lt_handle, fw_CPU, sizeof(fw_CPU), fw_SPECT, sizeof(fw_SPECT));
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_do_mutable_fw_update() failed, ret=%s\n", lt_ret_verbose(ret));
        fprintf(stderr,
                "Tip: turn logging on to see more information (compile with -DLT_LOG_LVL=Info)\n");
#if LT_DISABLE_MAINTENANCE_MODE
        if (g_maintenance_mode_was_enabled) {
            fprintf(stderr,
                    "WARNING: Due to the error, Maintenance Mode was kept enabled in R-Config!\n");
        }
#endif
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    if (get_fw_versions(&lt_handle) != LT_OK) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }

#if LT_DISABLE_MAINTENANCE_MODE
    // Warning: User shall disable Maintenance Mode only after both FW banks are updated with the
    // latest FW. If only one bank is updated (while the second one contains invalid FW), and
    // Maintenance Mode is disabled, the probability of bricking TROPIC01 increases. In this case, if
    // lt_do_mutable_fw_update() succeeds, it is safe to disable Maintenance Mode.
    if (LT_OK != disable_maintenance_mode(&lt_handle)) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
#else
    printf(
        "\nWARNING: We strongly recommend disabling Maintenance Mode in R-Config to reduce the attack "
        "surface.\n");
#endif

    printf("\nDeinitializing handle...");
    ret = lt_deinit(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to deinitialize handle, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    /* Cryptographic function provider deinitialization.

        In production, this would be done only once, typically
        during termination of the application. */
    mbedtls_psa_crypto_free();

    /* libtropic related code END */
    /* libtropic related code END */
    /* libtropic related code END */
    /* libtropic related code END */
    /* libtropic related code END */

    /* Not strictly necessary, but we deinitialize RNG here to demonstrate proper usage. */
    if (HAL_RNG_DeInit(&hrng) != HAL_OK) {
        Error_Handler();
    }

    while (1) {
    }
}

/**
 * @brief System Clock Configuration
 * @retval None
 */
void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    /** Configure the main internal regulator output voltage
     */
    if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK) {
        Error_Handler();
    }

    /** Initializes the CPU, AHB and APB buses clocks
     */
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI48 | RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
    RCC_OscInitStruct.PLL.PLLMBOOST = RCC_PLLMBOOST_DIV1;
    RCC_OscInitStruct.PLL.PLLM = 1;
    RCC_OscInitStruct.PLL.PLLN = 10;
    RCC_OscInitStruct.PLL.PLLP = 2;
    RCC_OscInitStruct.PLL.PLLQ = 2;
    RCC_OscInitStruct.PLL.PLLR = 1;
    RCC_OscInitStruct.PLL.PLLRGE = RCC_PLLVCIRANGE_0;
    RCC_OscInitStruct.PLL.PLLFRACN = 0;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
        Error_Handler();
    }

    /** Initializes the CPU, AHB and APB buses clocks
     */
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 |
                                  RCC_CLOCKTYPE_PCLK2 | RCC_CLOCKTYPE_PCLK3;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief Power Configuration
 * @retval None
 */
static void SystemPower_Config(void)
{
    /*
     * Switch to SMPS regulator instead of LDO
     */
    if (HAL_PWREx_ConfigSupply(PWR_SMPS_SUPPLY) != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief ICACHE Initialization Function
 * @param None
 * @retval None
 */
static void MX_ICACHE_Init(void)
{
    /** Enable instruction cache in 1-way (direct mapped cache)
     */
    if (HAL_ICACHE_ConfigAssociativityMode(ICACHE_1WAY) != HAL_OK) {
        Error_Handler();
    }
    if (HAL_ICACHE_Enable() != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief RNG Initialization Function
 * @param None
 * @retval None
 */
static void MX_RNG_Init(void)
{
    hrng.Instance = RNG;
    hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
    if (HAL_RNG_Init(&hrng) != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief USART1 Initialization Function
 * @param None
 * @retval None
 */
static void MX_USART1_UART_Init(void)
{
    huart1.Instance = USART1;
    huart1.Init.BaudRate = 115200;
    huart1.Init.WordLength = UART_WORDLENGTH_8B;
    huart1.Init.StopBits = UART_STOPBITS_1;
    huart1.Init.Parity = UART_PARITY_NONE;
    huart1.Init.Mode = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
    huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
    huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
    if (HAL_UART_Init(&huart1) != HAL_OK) {
        Error_Handler();
    }
    if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK) {
        Error_Handler();
    }
    if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK) {
        Error_Handler();
    }
    if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief GPIO Initialization Function
 * @param None
 * @retval None
 */
static void MX_GPIO_Init(void)
{
    /* GPIO Ports Clock Enable */
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
}

/**
 * @brief  Retargets the C library printf function to the USART.
 * @param  None
 * @retval None
 */
PUTCHAR_PROTOTYPE
{
    /*  Translates LF to CFLF, as this is what most serial monitors expect
        by default
    */
    if (ch == '\n') {
        HAL_UART_Transmit(&huart1, (uint8_t *)"\r\n", 2, 0xFFFF);
    }
    else {
        HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 0xFFFF);
    }

    return ch;
}

/**
 * @brief  This function is executed in case of error occurrence.
 * @retval None
 */
void Error_Handler(void)
{
    __disable_irq();
    while (1) {
    }
}
#ifdef USE_FULL_ASSERT
/**
 * @brief  Reports the name of the source file and the source line number
 *         where the assert_param error has occurred.
 * @param  file: pointer to the source file name
 * @param  line: assert_param error line source number
 * @retval None
 */
void assert_failed(uint8_t *file, uint32_t line)
{
    /* User can add his own implementation to report the file name and line number,
       ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

    /* Infinite loop */
    while (1) {
    }
}
#endif /* USE_FULL_ASSERT */
