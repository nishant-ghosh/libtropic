/**
 * @file lt_test_mock_invalid_in_crc.c
 * @brief Test for handling invalid CRC in TROPIC01 responses.
 * @copyright Copyright (c) 2020-2026 Tropic Square s.r.o.
 *
 * @license For the license see LICENSE.md in the root directory of this source tree.
 */

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_logging.h"
#include "libtropic_port_mock.h"
#include "lt_functional_mock_tests.h"
#include "lt_l1.h"
#include "lt_l2_api_structs.h"
#include "lt_l2_frame_check.h"
#include "lt_mock_helpers.h"
#include "lt_test_common.h"

void lt_test_mock_invalid_in_crc(lt_handle_t *h)
{
    LT_LOG_INFO("----------------------------------------------");
    LT_LOG_INFO("lt_test_mock_invalid_in_crc()");
    LT_LOG_INFO("----------------------------------------------");

    if (LT_CRC_ERR_RETRY_ATTEMPTS < 1) {
        LT_LOG_ERROR("This test requires that at least one retry attempt is configured.");
        LT_TEST_ASSERT(0, 1);  // Forcefully fail the test.
    }

    // 1. Mock init sequence and initialize Libtropic handle
    // ---------------------------------------------------------------------------------------------

    lt_mock_hal_reset(&h->l2);
    LT_LOG_INFO("Mocking initialization...");
    LT_TEST_ASSERT(LT_OK,
                   mock_init_communication(h, (uint8_t[]){0x00, 0x00, 0x00, 0x02}));  // Version 2.0.0

    LT_LOG_INFO("Initializing handle");
    LT_TEST_ASSERT(LT_OK, lt_init(h));

    // 2. Deplete all retry attempts and check if LT_L2_IN_CRC_ERR was returned.
    // ---------------------------------------------------------------------------------------------

    const uint8_t chip_ready = TR01_L1_CHIP_MODE_READY_bit;
    struct lt_l2_get_info_rsp_t get_info_resp_corrupted_crc = {
        .chip_status = TR01_L1_CHIP_MODE_READY_bit,
        .status = TR01_L2_STATUS_REQUEST_OK,
        .rsp_len = TR01_L2_GET_INFO_RISCV_FW_SIZE,
        .object = {0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF}  // dummy data with invalid CRC appended
    };
    uint8_t dummy_out[TR01_L2_GET_INFO_RISCV_FW_SIZE];

    // Enqueue count of responses based on configured resend attempts.
    // 1 + LT_CRC_ERR_RETRY_ATTEMPTS, because first is normal Request, remaining are retries.
    for (int i = 0; i < 1 + LT_CRC_ERR_RETRY_ATTEMPTS; i++) {
        LT_TEST_ASSERT(LT_OK, lt_mock_hal_enqueue_response(&h->l2, &chip_ready, sizeof(chip_ready)));
        LT_TEST_ASSERT(
            LT_OK, lt_mock_hal_enqueue_response(&h->l2, (uint8_t *)&get_info_resp_corrupted_crc,
                                                calc_mocked_resp_len(&get_info_resp_corrupted_crc)));
    }

    LT_LOG_INFO("Sending Get_Info request with invalid CRC in response...");
    LT_TEST_ASSERT(LT_L2_IN_CRC_ERR, lt_get_info_riscv_fw_ver(h, dummy_out));

    // 3. Send one corrupted frame and then a correct one and check if LT_OK is returned.
    // ---------------------------------------------------------------------------------------------

    LT_TEST_ASSERT(LT_OK, lt_mock_hal_enqueue_response(&h->l2, &chip_ready, sizeof(chip_ready)));
    LT_TEST_ASSERT(LT_OK,
                   lt_mock_hal_enqueue_response(&h->l2, (uint8_t *)&get_info_resp_corrupted_crc,
                                                calc_mocked_resp_len(&get_info_resp_corrupted_crc)));

    LT_TEST_ASSERT(LT_OK, lt_mock_hal_enqueue_response(&h->l2, &chip_ready, sizeof(chip_ready)));
    struct lt_l2_get_info_rsp_t get_info_resp = {.chip_status = TR01_L1_CHIP_MODE_READY_bit,
                                                 .status = TR01_L2_STATUS_REQUEST_OK,
                                                 .rsp_len = TR01_L2_GET_INFO_RISCV_FW_SIZE,
                                                 .object = {0x00, 0x00, 0x00, 0x02}};
    add_resp_crc(&get_info_resp);
    LT_TEST_ASSERT(LT_OK, lt_mock_hal_enqueue_response(&h->l2, (uint8_t *)&get_info_resp,
                                                       calc_mocked_resp_len(&get_info_resp)));

    LT_LOG_INFO("Sending Get_Info request with correct CRC...");
    LT_TEST_ASSERT(LT_OK, lt_get_info_riscv_fw_ver(h, dummy_out));

    // 4. Deinitialize Libtropic handle
    // ---------------------------------------------------------------------------------------------

    LT_LOG_INFO("Deinitializing handle");
    LT_TEST_ASSERT(LT_OK, lt_deinit(h));
}