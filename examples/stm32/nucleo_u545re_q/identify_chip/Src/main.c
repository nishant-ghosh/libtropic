/**
 * @file main.c
 * @brief Example of reading information about the TROPIC01 chip and its firmware using Libtropic on
 * STM32 Nucleo U545RE-Q board.
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
#include <string.h>

#include "libtropic.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_stm32u5xx.h"
#include "psa/crypto.h"

/* Private define ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* RNG handle declaration */
RNG_HandleTypeDef hrng;

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

    printf("==============================================\n");
    printf("==== TROPIC01 Chip Identification Example ====\n");
    printf("==============================================\n");

    /* Cryptographic function provider initialization.

        In production, this would typically be done only once,
        usually at the start of the application or before
        the first use of cryptographic functions but no later than
        the first occurrence of any Libtropic function */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "PSA Crypto initialization failed, status=%ld (psa_status_t)\n", status);
        Error_Handler();
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
        Error_Handler();
    }
    printf("OK\n");

    /* First, we check versions of both updateable firmwares. To do that, we need TROPIC01 to **not**
       be in the Start-up Mode. If there are valid firmwares, TROPIC01 will begin to execute them
       automatically on boot. */
    printf("Sending reboot request...");
    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    printf("OK\n");

    printf("Reading data from chip...\n");

    uint8_t fw_ver[4];
    ret = lt_get_info_riscv_fw_ver(&lt_handle, fw_ver);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to get RISC-V FW version, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    printf("  RISC-V FW version: %" PRIX8 ".%" PRIX8 ".%" PRIX8 " (.%" PRIX8 ")\n", fw_ver[3],
           fw_ver[2], fw_ver[1], fw_ver[0]);

    ret = lt_get_info_spect_fw_ver(&lt_handle, fw_ver);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to get SPECT FW version, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    printf("  SPECT FW version: %" PRIX8 ".%" PRIX8 ".%" PRIX8 " (.%" PRIX8 ")\n", fw_ver[3],
           fw_ver[2], fw_ver[1], fw_ver[0]);

    /* We need to do the maintenance reboot to check bootloader version and FW bank headers in the
     * Startup Mode. */
    printf("Sending maintenance reboot request...");
    ret = lt_reboot(&lt_handle, TR01_MAINTENANCE_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    printf("OK\n");

    printf("Reading data from chip...\n");

    /* When TROPIC01 is in Start-up Mode, we can get RISC-V bootloader version the same way as we got
     * RISC-V FW version.
     */
    ret = lt_get_info_riscv_fw_ver(&lt_handle, fw_ver);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to get RISC-V bootloader version, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    printf("  RISC-V bootloader version: %" PRIX8 ".%" PRIX8 ".%" PRIX8 " (.%" PRIX8 ")\n",
           fw_ver[3] & 0x7f, fw_ver[2], fw_ver[1], fw_ver[0]);

    printf("Firmware bank headers:\n");
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_FW1, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_FW1 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_FW2, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_FW2 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_SPECT1, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_SPECT1 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_SPECT2, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_SPECT2 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }

    struct lt_chip_id_t chip_id = {0};

    printf("Chip ID data:\n");
    ret = lt_get_info_chip_id(&lt_handle, &chip_id);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to get chip ID, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }

    printf("---------------------------------------------------------\n");
    ret = lt_print_chip_id(&chip_id, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print chip ID, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    printf("---------------------------------------------------------\n");

    printf("Sending reboot request...");
    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        Error_Handler();
    }
    printf("OK!\n");

    printf("Deinitializing handle...");
    ret = lt_deinit(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to deinitialize handle, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        Error_Handler();
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
    HAL_StatusTypeDef hal_ret = HAL_RNG_DeInit(&hrng);
    if (hal_ret != HAL_OK) {
        fprintf(stderr, "HAL_RNG_DeInit() failed, hal_ret=%u\n", hal_ret);
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
    fprintf(stderr, "Error_Handler() was called!\n");

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
