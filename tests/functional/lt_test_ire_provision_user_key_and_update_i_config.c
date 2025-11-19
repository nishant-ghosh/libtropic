/**
 * @file lt_test_ire_provision_admin_key.c
 * @brief Provision user key (SH2) using SH1 and update R-config
 * @author Nishant Ghosh <nishant.ghosh@toolsforhumanity.com>
 * 
 * Test flow to provision pairing keys, configure R-config, and provision some ECC keys.
 * In the real factory flow, the I-config is also updated, but since it's irreversible, 
 * we're testing everything with R-config.
 */

#include <inttypes.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_functional_tests.h"
#include "libtropic_logging.h"
#include "lt_random.h"
#include "string.h"

/**
 * @brief Creates an R-config object
 *
 * @param r_config R-config to modify
 */
static void create_r_config(struct lt_config_t *r_config)
{
    //-------CFG_START_UP------------------------------------
    // Keep at reset value

    //-------CFG_SENSORS-------------------------------------
    // Keep at reset value

    //-------CFG_DEBUG---------------------------------------
    // Keep at reset value

    //-------TR01_CFG_GPO-----------------------------------------
    // Keep at reset value

    //-------TR01_CFG_SLEEP_MODE----------------------------------
    // Disable sleep mode
    r_config->obj[TR01_CFG_SLEEP_MODE_IDX] &= ~(APPLICATION_CO_CFG_SLEEP_MODE_SLEEP_MODE_EN_MASK);

    //------- TR01_CFG_UAP_PAIRING_KEY_WRITE ---------------------
    // Disable write privileges for all keys except admin key
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH2(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH3(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_PAIRING_KEY_READ ----------------------
    // Admin and User keys can read all pairing keys
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH2(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH3(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_PAIRING_KEY_INVALIDATE ----------------
    // Admin and delete-all keys can invalidate all pairing keys
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_INVALIDATE_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | !(LT_SESSION_SH3_HAS_ACCESS));
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_INVALIDATE_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | !(LT_SESSION_SH3_HAS_ACCESS));
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_INVALIDATE_IDX] &= ~LT_TO_PAIRING_KEY_SH2(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | !(LT_SESSION_SH3_HAS_ACCESS));
    r_config->obj[TR01_CFG_UAP_PAIRING_KEY_INVALIDATE_IDX] &= ~LT_TO_PAIRING_KEY_SH3(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | !(LT_SESSION_SH3_HAS_ACCESS));

    //------- TR01_CFG_UAP_R_CONFIG_WRITE_ERASE ------------------
    // Admin and User keys can write/erase R-config
    r_config->obj[TR01_CFG_UAP_R_CONFIG_WRITE_ERASE_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_R_CONFIG_READ -------------------------
    // Admin and User keys can read R-config
    r_config->obj[TR01_CFG_UAP_R_CONFIG_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
        r_config->obj[TR01_CFG_UAP_R_CONFIG_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_I_CONFIG_WRITE ------------------------
    // Only admin key has I-config write privileges
    r_config->obj[TR01_CFG_UAP_I_CONFIG_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
        r_config->obj[TR01_CFG_UAP_I_CONFIG_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_I_CONFIG_READ -------------------------
    // Admin and user keys have I-config read privileges
    r_config->obj[TR01_CFG_UAP_I_CONFIG_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
        r_config->obj[TR01_CFG_UAP_I_CONFIG_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_PING ----------------------------------
    // Enable for all pairing keys
    r_config->obj[TR01_CFG_UAP_PING_IDX] |= (LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS
                                             | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_R_MEM_DATA_WRITE ----------------------
    // 
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH2(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_WRITE_IDX] &= ~LT_TO_PAIRING_KEY_SH3(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_R_MEM_DATA_READ -----------------------
    // 
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH2(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_READ_IDX] &= ~LT_TO_PAIRING_KEY_SH3(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_R_MEM_DATA_ERASE ----------------------
    // 
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_ERASE_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_ERASE_IDX] &= ~LT_TO_PAIRING_KEY_SH1(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_ERASE_IDX] &= ~LT_TO_PAIRING_KEY_SH2(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_R_MEM_DATA_ERASE_IDX] &= ~LT_TO_PAIRING_KEY_SH3(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_RANDOM_VALUE_GET ----------------------
    // Enable for admin and user pairing keys
    r_config->obj[TR01_CFG_UAP_RANDOM_VALUE_GET_IDX] &= ~LT_TO_PAIRING_KEY_SH0(
        LT_SESSION_SH0_HAS_ACCESS | !(LT_SESSION_SH1_HAS_ACCESS) | !(LT_SESSION_SH2_HAS_ACCESS) | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_ECC_KEY_GENERATE ----------------------
    // 1. Disable all, then enable only specific ones
    r_config->obj[TR01_CFG_UAP_ECC_KEY_GENERATE_IDX] &= ~LT_TO_ECC_KEY_SLOT_0_7(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_GENERATE_IDX] &= ~LT_TO_ECC_KEY_SLOT_8_15(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_GENERATE_IDX] &= ~LT_TO_ECC_KEY_SLOT_16_23(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_GENERATE_IDX] &= ~LT_TO_ECC_KEY_SLOT_24_31(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // 2. Only session with SH1PUB can generate keys in slots 0-7
    r_config->obj[TR01_CFG_UAP_ECC_KEY_GENERATE_IDX]
        |= (LT_TO_ECC_KEY_SLOT_0_7(LT_SESSION_SH1_HAS_ACCESS));
    // 3. Only session with SH1PUB, SH2PUB can generate keys in slots 8-31
    r_config->obj[TR01_CFG_UAP_ECC_KEY_GENERATE_IDX]
        |= (LT_TO_ECC_KEY_SLOT_8_15(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS) | 
            LT_TO_ECC_KEY_SLOT_16_23(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS)| 
            LT_TO_ECC_KEY_SLOT_24_31(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS));

    //------- TR01_CFG_UAP_ECC_KEY_STORE -------------------------
    // 1. Disable all
    r_config->obj[TR01_CFG_UAP_ECC_KEY_STORE_IDX] &= ~LT_TO_ECC_KEY_SLOT_0_7(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_STORE_IDX] &= ~LT_TO_ECC_KEY_SLOT_8_15(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_STORE_IDX] &= ~LT_TO_ECC_KEY_SLOT_16_23(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_STORE_IDX] &= ~LT_TO_ECC_KEY_SLOT_24_31(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // // 2. Session with SH1PUB can store key into ECC key slot 0-7
    // r_config->obj[TR01_CFG_UAP_ECC_KEY_STORE_IDX] |= LT_TO_ECC_KEY_SLOT_0_7(LT_SESSION_SH1_HAS_ACCESS);
    // // 3. Session with SH3PUB can store key into ECC key slot 8-31
    // r_config->obj[TR01_CFG_UAP_ECC_KEY_STORE_IDX] |= LT_TO_ECC_KEY_SLOT_8_15(LT_SESSION_SH3_HAS_ACCESS)
    //                                                  | LT_TO_ECC_KEY_SLOT_16_23(LT_SESSION_SH3_HAS_ACCESS)
    //                                                  | LT_TO_ECC_KEY_SLOT_24_31(LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_ECC_KEY_READ --------------------------
    // Enable for all pairing keys except SH0PUB
    r_config->obj[TR01_CFG_UAP_ECC_KEY_READ_IDX] &= ~LT_TO_ECC_KEY_SLOT_0_7(
        !(LT_SESSION_SH0_HAS_ACCESS) | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_READ_IDX] &= ~LT_TO_ECC_KEY_SLOT_8_15(
        !(LT_SESSION_SH0_HAS_ACCESS) | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_READ_IDX] &= ~LT_TO_ECC_KEY_SLOT_16_23(
        !(LT_SESSION_SH0_HAS_ACCESS) | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_READ_IDX] &= ~LT_TO_ECC_KEY_SLOT_24_31(
        !(LT_SESSION_SH0_HAS_ACCESS) | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_ECC_KEY_ERASE -------------------------
    // 1. Disable all, then enable only specific ones
    r_config->obj[TR01_CFG_UAP_ECC_KEY_ERASE_IDX] &= ~LT_TO_ECC_KEY_SLOT_0_7(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_ERASE_IDX] &= ~LT_TO_ECC_KEY_SLOT_8_15(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_ERASE_IDX] &= ~LT_TO_ECC_KEY_SLOT_16_23(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECC_KEY_ERASE_IDX] &= ~LT_TO_ECC_KEY_SLOT_24_31(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // 2. Session with SH1PUB, SH3PUB can erase ECC key slots 0-7
    r_config->obj[TR01_CFG_UAP_ECC_KEY_ERASE_IDX] |= LT_TO_ECC_KEY_SLOT_0_7(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // 3. Session with SH1PUB, SH2PUB, SH3PUB can erase ECC key slots 8-31
    r_config->obj[TR01_CFG_UAP_ECC_KEY_ERASE_IDX] |= LT_TO_ECC_KEY_SLOT_8_15(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS)
                                                     | LT_TO_ECC_KEY_SLOT_16_23(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS)
                                                     | LT_TO_ECC_KEY_SLOT_24_31(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);

    //------- TR01_CFG_UAP_ECDSA_SIGN ----------------------------
    // 1. Disable all, then enable only specific ones
    r_config->obj[TR01_CFG_UAP_ECDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_0_7(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_8_15(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_16_23(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_ECDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_24_31(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // 2. Session with SH1PUB can sign with ECC key slots 0-7
    r_config->obj[TR01_CFG_UAP_ECDSA_SIGN_IDX]
        |= (LT_TO_ECC_KEY_SLOT_0_7(LT_SESSION_SH1_HAS_ACCESS));
    // 3. Session with SH1PUB, SH2PUB can sign with keys in slots 8-31
    r_config->obj[TR01_CFG_UAP_ECDSA_SIGN_IDX]
        |= (LT_TO_ECC_KEY_SLOT_8_15(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS) | 
            LT_TO_ECC_KEY_SLOT_16_23(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS)| 
            LT_TO_ECC_KEY_SLOT_24_31(LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS));

    //------- TR01_CFG_UAP_EDDSA_SIGN ----------------------------
    // 1. Disable all, then enable only specific ones
    r_config->obj[TR01_CFG_UAP_EDDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_0_7(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_EDDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_8_15(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_EDDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_16_23(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    r_config->obj[TR01_CFG_UAP_EDDSA_SIGN_IDX] &= ~LT_TO_ECC_KEY_SLOT_24_31(
        LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // // 2. Session with SH3PUB can sign with all ECC key slots
    // r_config->obj[TR01_CFG_UAP_EDDSA_SIGN_IDX]
    //     |= (LT_TO_ECC_KEY_SLOT_0_7(LT_SESSION_SH3_HAS_ACCESS) | LT_TO_ECC_KEY_SLOT_8_15(LT_SESSION_SH3_HAS_ACCESS)
    //         | LT_TO_ECC_KEY_SLOT_16_23(LT_SESSION_SH3_HAS_ACCESS)
    //         | LT_TO_ECC_KEY_SLOT_24_31(LT_SESSION_SH3_HAS_ACCESS));

    //------- TR01_CFG_UAP_MCOUNTER_INIT -------------------------
    // Keep at reset
    // // 1. Disable all, then enable only specific ones
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_INIT_IDX] &= ~LT_TO_MCOUNTER_0_3(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_INIT_IDX] &= ~LT_TO_MCOUNTER_4_7(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_INIT_IDX] &= ~LT_TO_MCOUNTER_8_11(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_INIT_IDX] &= ~LT_TO_MCOUNTER_12_15(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // // 2. Session with SH3PUB can init all mcounters
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_INIT_IDX]
    //     |= (LT_TO_MCOUNTER_0_3(LT_SESSION_SH3_HAS_ACCESS) | LT_TO_MCOUNTER_4_7(LT_SESSION_SH3_HAS_ACCESS)
    //         | LT_TO_MCOUNTER_8_11(LT_SESSION_SH3_HAS_ACCESS) | LT_TO_MCOUNTER_12_15(LT_SESSION_SH3_HAS_ACCESS));

    //------- TR01_CFG_UAP_MCOUNTER_GET --------------------------
    // Keep at reset
    // // 1. Disable all, then enable only specific ones
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_GET_IDX] &= ~LT_TO_MCOUNTER_0_3(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_GET_IDX] &= ~LT_TO_MCOUNTER_4_7(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_GET_IDX] &= ~LT_TO_MCOUNTER_8_11(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_GET_IDX] &= ~LT_TO_MCOUNTER_12_15(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // // 2. Session with SH3PUB can get all mcounters
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_GET_IDX]
    //     |= (LT_TO_MCOUNTER_0_3(LT_SESSION_SH3_HAS_ACCESS) | LT_TO_MCOUNTER_4_7(LT_SESSION_SH3_HAS_ACCESS)
    //         | LT_TO_MCOUNTER_8_11(LT_SESSION_SH3_HAS_ACCESS) | LT_TO_MCOUNTER_12_15(LT_SESSION_SH3_HAS_ACCESS));

    //------- TR01_CFG_UAP_MCOUNTER_UPDATE -----------------------
    // Keep at reset
    // // 1. Disable all, then enable only specific ones
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_UPDATE_IDX] &= ~LT_TO_MCOUNTER_0_3(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_UPDATE_IDX] &= ~LT_TO_MCOUNTER_4_7(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_UPDATE_IDX] &= ~LT_TO_MCOUNTER_8_11(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_UPDATE_IDX] &= ~LT_TO_MCOUNTER_12_15(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // // 2. Session with SH3PUB can update all mcounters
    // r_config->obj[TR01_CFG_UAP_MCOUNTER_UPDATE_IDX]
    //     |= (LT_TO_MCOUNTER_0_3(LT_SESSION_SH3_HAS_ACCESS) | LT_TO_MCOUNTER_4_7(LT_SESSION_SH3_HAS_ACCESS)
    //         | LT_TO_MCOUNTER_8_11(LT_SESSION_SH3_HAS_ACCESS) | LT_TO_MCOUNTER_12_15(LT_SESSION_SH3_HAS_ACCESS));

    //------- TR01_CFG_UAP_MAC_AND_DESTROY_ADDR -----------------------
    // Keep at reset
    // Enable for all pairing key slots
    // r_config->obj[TR01_CFG_UAP_MAC_AND_DESTROY_IDX] |= LT_TO_MACANDD_SLOT_0_31(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MAC_AND_DESTROY_IDX] |= LT_TO_MACANDD_SLOT_32_63(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MAC_AND_DESTROY_IDX] |= LT_TO_MACANDD_SLOT_64_95(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
    // r_config->obj[TR01_CFG_UAP_MAC_AND_DESTROY_IDX] |= LT_TO_MACANDD_SLOT_96_127(
    //     LT_SESSION_SH0_HAS_ACCESS | LT_SESSION_SH1_HAS_ACCESS | LT_SESSION_SH2_HAS_ACCESS | LT_SESSION_SH3_HAS_ACCESS);
}

void lt_test_ire_provision_user_key_and_update_r_config(lt_handle_t *h)
{
    LT_LOG_INFO("----------------------------------------------");
    LT_LOG_INFO("lt_test_ire_provision_user_key_and_update_r_config()");
    LT_LOG_INFO("----------------------------------------------");

    uint8_t *pub_keys[] = {sh2pub, sh3pub};
    uint8_t *priv_keys[] = {sh2priv, sh3priv};
    uint8_t read_key[TR01_SHIPUB_LEN] = {0};
    char print_buff[PRINT_BUFF_SIZE];
    
    struct lt_config_t r_config, r_config_read;

    LT_LOG_INFO("Initializing handle");
    LT_TEST_ASSERT(LT_OK, lt_init(h));

    LT_LOG_INFO("Starting Secure Session with key %d", (int)TR01_PAIRING_KEY_SLOT_INDEX_1);
    LT_TEST_ASSERT(LT_OK, lt_verify_chip_and_start_secure_session(h, sh0priv, sh0pub, TR01_PAIRING_KEY_SLOT_INDEX_0));
    LT_LOG_LINE();
    
    /* Dumb in-line flow without any function calls */ 
    // Write user pairing key into slot 2
    LT_LOG_INFO("Writing to pairing key slot %" PRIu8 "...", 2);
    LT_TEST_ASSERT(LT_OK, lt_print_bytes(pub_keys[0], TR01_SHIPUB_LEN, print_buff, PRINT_BUFF_SIZE));
    LT_LOG_INFO("%s", print_buff);
    LT_TEST_ASSERT(LT_OK, lt_pairing_key_write(h, pub_keys[0], 2));
    LT_LOG_INFO();
    LT_LOG_LINE();

    // Check pairing key written in slot 2
    LT_LOG_INFO("Reading pairing key slot %" PRIu8 "...", 2);
    LT_TEST_ASSERT(LT_OK, lt_pairing_key_read(h, read_key, 2));
    LT_TEST_ASSERT(LT_OK, lt_print_bytes(read_key, sizeof(read_key), print_buff, PRINT_BUFF_SIZE));
    LT_LOG_INFO("%s", print_buff);

    LT_LOG_INFO("Comparing contents of written and read key...");
    LT_TEST_ASSERT(0, memcmp(pub_keys[0], read_key, TR01_SHIPUB_LEN));
    LT_LOG_INFO();

    // Write delete-all pairing key into slot 3
    LT_LOG_INFO("Writing to pairing key slot %" PRIu8 "...", 3);
    LT_TEST_ASSERT(LT_OK, lt_print_bytes(pub_keys[1], TR01_SHIPUB_LEN, print_buff, PRINT_BUFF_SIZE));
    LT_LOG_INFO("%s", print_buff);
    LT_TEST_ASSERT(LT_OK, lt_pairing_key_write(h, pub_keys[1], 3));
    LT_LOG_INFO();
    LT_LOG_LINE();

    // Check pairing key written in slot 3
    LT_LOG_INFO("Reading pairing key slot %" PRIu8 "...", 3);
    LT_TEST_ASSERT(LT_OK, lt_pairing_key_read(h, read_key, 3));
    LT_TEST_ASSERT(LT_OK, lt_print_bytes(read_key, sizeof(read_key), print_buff, PRINT_BUFF_SIZE));
    LT_LOG_INFO("%s", print_buff);

    LT_LOG_INFO("Comparing contents of written and read key...");
    LT_TEST_ASSERT(0, memcmp(pub_keys[3], read_key, TR01_SHIPUB_LEN));
    LT_LOG_INFO();

    LT_LOG_INFO("Erasing R config in case it is already written...");
    ret = lt_r_config_erase(h);
    if (LT_OK != ret) {
        LT_LOG_ERROR("Failed to erase R config, ret=%s", lt_ret_verbose(ret));
        return -1;
    }
    LT_LOG_INFO("\tOK");

    LT_LOG_INFO("Reading the whole R config:");
    ret = lt_read_whole_R_config(h, &r_config);
    if (LT_OK != ret) {
        LT_LOG_ERROR("Failed to read R config, ret=%s", lt_ret_verbose(ret));
        return -1;
    }
    for (int i = 0; i < LT_CONFIG_OBJ_CNT; i++) {
        LT_LOG_INFO("%s: 0x%08" PRIx32, cfg_desc_table[i].desc, r_config.obj[i]);
    }

    // LT_LOG_INFO("Creating R config object from the read r-config...");
    // create_r_config(&r_config);

    // // Configure R-config
    // LT_LOG_INFO("Writing the whole R config with the example config...");
    // ret = lt_write_whole_R_config(h, &r_config);
    // if (LT_OK != ret) {
    //     LT_LOG_ERROR("Failed to write R config, ret=%s", lt_ret_verbose(ret));
    //     return -1;
    // }
    // LT_LOG_INFO("\tOK");

    // LT_LOG_INFO("Reading the whole R config again:");
    // ret = lt_read_whole_R_config(h, &r_config);
    // if (LT_OK != ret) {
    //     LT_LOG_ERROR("Failed to read R config, ret=%s", lt_ret_verbose(ret));
    //     return -1;
    // }
    // for (int i = 0; i < LT_CONFIG_OBJ_CNT; i++) {
    //     LT_LOG_INFO("%s: 0x%08" PRIx32, cfg_desc_table[i].desc, r_config.obj[i]);
    // }
    // LT_LOG_LINE();

    LT_LOG_INFO("Aborting Secure Session");
    LT_TEST_ASSERT(LT_OK, lt_session_abort(h));

    LT_LOG_INFO("Deinitializing handle");
    LT_TEST_ASSERT(LT_OK, lt_deinit(h));
}