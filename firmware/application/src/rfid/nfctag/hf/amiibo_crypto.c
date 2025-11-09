#include "amiibo_crypto.h"
#include <string.h>
#include "nrf_crypto.h"
#include "nrf_crypto_aes.h"
#include "nrf_crypto_hash.h"
#include "nrf_crypto_hmac.h"

#define NRF_LOG_MODULE_NAME amiibo_crypto
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
NRF_LOG_MODULE_REGISTER();

// Master key structure (80 bytes each section)
typedef struct {
    uint8_t hmac_key[16];
    uint8_t type_string[14];
    uint8_t reserved1;
    uint8_t magic_size;
    uint8_t magic[16];
    uint8_t reserved2[32];
} amiibo_master_key_t;

// Derived keys from DRBG
typedef struct {
    uint8_t aes_key[16];
    uint8_t aes_iv[16];
    uint8_t hmac_key[16];
} amiibo_derived_keys_t;

/**
 * Compute HMAC-SHA256
 */
static bool hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out) {
    ret_code_t ret;
    nrf_crypto_hmac_context_t hmac_ctx;
    size_t out_len = 32;

    ret = nrf_crypto_hmac_calculate(&hmac_ctx,
                                     &g_nrf_crypto_hmac_sha256_info,
                                     out,
                                     &out_len,
                                     key,
                                     key_len,
                                     data,
                                     data_len);

    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("HMAC-SHA256 failed: 0x%08X", ret);
        return false;
    }

    if (out_len != 32) {
        NRF_LOG_ERROR("HMAC output length: %d (expected 32)", out_len);
        return false;
    }

    return true;
}

/**
 * Derive keys using DRBG (Deterministic Random Bit Generator)
 * Matches the TagWallet Swift implementation
 */
static bool derive_keys(const amiibo_master_key_t *master_key,
                        const uint8_t *uid,
                        const uint8_t *write_counter,
                        const uint8_t *salt,
                        const uint8_t *xorpad,
                        bool include_write_counter,
                        amiibo_derived_keys_t *keys) {
    uint8_t seed[128];
    uint16_t seed_len = 0;

    // Build seed: type_string + [write_counter] + magic + uid + uid + (xorpad XOR salt)
    memcpy(&seed[seed_len], master_key->type_string, 14);
    seed_len += 14;

    // Add write counter if magic_size < 16
    if (include_write_counter && master_key->magic_size < 16) {
        memcpy(&seed[seed_len], write_counter, 2);
        seed_len += 2;
    }

    memcpy(&seed[seed_len], master_key->magic, master_key->magic_size);
    seed_len += master_key->magic_size;

    memcpy(&seed[seed_len], uid, 8);
    seed_len += 8;

    memcpy(&seed[seed_len], uid, 8);  // UID repeated
    seed_len += 8;

    // XOR salt with xorpad
    for (int i = 0; i < 32; i++) {
        seed[seed_len + i] = salt[i] ^ xorpad[i];
    }
    seed_len += 32;

    // Derive keys using HMAC-SHA256 with iterations
    uint8_t hmac_output_0[32];
    uint8_t hmac_output_1[32];
    uint8_t hmac_input[130];

    // Iteration 0: prefix = [0x00, 0x00]
    hmac_input[0] = 0x00;
    hmac_input[1] = 0x00;
    memcpy(&hmac_input[2], seed, seed_len);
    if (!hmac_sha256(master_key->hmac_key, 16, hmac_input, 2 + seed_len, hmac_output_0)) {
        return false;
    }

    // Iteration 1: prefix = [0x00, 0x01]
    hmac_input[0] = 0x00;
    hmac_input[1] = 0x01;
    memcpy(&hmac_input[2], seed, seed_len);
    if (!hmac_sha256(master_key->hmac_key, 16, hmac_input, 2 + seed_len, hmac_output_1)) {
        return false;
    }

    // Combine: output = hmac(iter0) + hmac(iter1)[0:16]
    // aes_key = output[0:16], aes_iv = output[16:32], hmac_key = output[32:48]
    memcpy(keys->aes_key, hmac_output_0, 16);
    memcpy(keys->aes_iv, &hmac_output_0[16], 16);
    memcpy(keys->hmac_key, hmac_output_1, 16);

    return true;
}

/**
 * AES-128-CTR decrypt/encrypt (same operation for CTR mode)
 */
static bool aes_ctr_crypt(uint8_t *key, uint8_t *iv,
                          uint8_t *input, size_t len, uint8_t *output) {
    ret_code_t ret;
    nrf_crypto_aes_context_t aes_ctx;
    size_t out_len = len;

    // Initialize AES-CTR context
    ret = nrf_crypto_aes_init(&aes_ctx,
                               &g_nrf_crypto_aes_ctr_128_info,
                               NRF_CRYPTO_ENCRYPT);
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("AES init failed: %d", ret);
        return false;
    }

    // Set key
    ret = nrf_crypto_aes_key_set(&aes_ctx, key);
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("AES key set failed: %d", ret);
        nrf_crypto_aes_uninit(&aes_ctx);
        return false;
    }

    // Set IV
    ret = nrf_crypto_aes_iv_set(&aes_ctx, iv);
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("AES IV set failed: %d", ret);
        nrf_crypto_aes_uninit(&aes_ctx);
        return false;
    }

    // Perform encryption/decryption
    ret = nrf_crypto_aes_finalize(&aes_ctx, input, len, output, &out_len);

    nrf_crypto_aes_uninit(&aes_ctx);

    if (ret != NRF_SUCCESS || out_len != len) {
        NRF_LOG_ERROR("AES crypt failed: %d, out_len=%d", ret, out_len);
        return false;
    }

    return true;
}

/**
 * AES-128-CTR decrypt/encrypt for Amiibo's two-part encrypted data
 * This function handles the encrypted data in two non-contiguous parts with a continuous counter.
 *
 * In Amiibo tags, encrypted data is split across two regions:
 * - Part 1: bytes 20-52 (32 bytes)
 * - Part 2: bytes 160-520 (360 bytes)
 *
 * These must be encrypted/decrypted as one continuous 392-byte stream to maintain
 * the correct AES-CTR counter sequence.
 */
static bool aes_ctr_crypt_amiibo_data(uint8_t *key, uint8_t *iv,
                                      const uint8_t *part1_input, size_t part1_len,
                                      const uint8_t *part2_input, size_t part2_len,
                                      uint8_t *part1_output, uint8_t *part2_output) {
    // Create a continuous buffer for the combined encrypted data
    uint8_t combined_input[AMIIBO_ENCRYPTED_DATA_SIZE];  // 392 bytes
    uint8_t combined_output[AMIIBO_ENCRYPTED_DATA_SIZE];

    // Combine both parts into a single buffer
    memcpy(combined_input, part1_input, part1_len);
    memcpy(&combined_input[part1_len], part2_input, part2_len);

    // Encrypt/decrypt the combined data in one operation with continuous counter
    if (!aes_ctr_crypt(key, iv, combined_input, part1_len + part2_len, combined_output)) {
        return false;
    }

    // Split the result back into two parts
    memcpy(part1_output, combined_output, part1_len);
    memcpy(part2_output, &combined_output[part1_len], part2_len);

    return true;
}

/**
 * Check if tag data appears to be a valid Amiibo
 */
bool amiibo_is_valid(const uint8_t *tag_data) {
    if (tag_data == NULL) {
        return false;
    }

    // Check for typical Amiibo patterns:
    // 1. Byte 16 should be 0xA5 (typical for Amiibo)
    // 2. Tag HMAC should not be all zeros
    // 3. Data HMAC should not be all zeros

    if (tag_data[16] != 0xA5) {
        return false;
    }

    // Check Tag HMAC not all zeros
    bool tag_hmac_nonzero = false;
    for (int i = 0; i < AMIIBO_HMAC_SIZE; i++) {
        if (tag_data[AMIIBO_OFFSET_TAG_HMAC + i] != 0) {
            tag_hmac_nonzero = true;
            break;
        }
    }

    // Check Data HMAC not all zeros
    bool data_hmac_nonzero = false;
    for (int i = 0; i < AMIIBO_HMAC_SIZE; i++) {
        if (tag_data[AMIIBO_OFFSET_DATA_HMAC + i] != 0) {
            data_hmac_nonzero = true;
            break;
        }
    }

    return (tag_hmac_nonzero && data_hmac_nonzero);
}

/**
 * Re-encrypt Amiibo data with a new UID
 */
bool amiibo_reencrypt_with_new_uid(uint8_t *tag_data, const uint8_t *new_uid,
                                    const uint8_t *old_uid, const uint8_t *keys) {
    if (tag_data == NULL || new_uid == NULL || old_uid == NULL || keys == NULL) {
        NRF_LOG_ERROR("NULL pointer in amiibo_reencrypt");
        return false;
    }

    // nRF crypto library requires all input data to be in RAM, not flash
    // Copy the keys from flash to a temporary RAM buffer
    uint8_t keys_ram[160];
    memcpy(keys_ram, keys, 160);

    // Parse master keys from RAM buffer
    // Key file structure (160 bytes total):
    // - data_key (80 bytes at offset 0)
    // - tag_key (80 bytes at offset 80)
    // - xorpad is embedded in tag_key.reserved2 (32 bytes at offset 128)
    const amiibo_master_key_t *data_key = (const amiibo_master_key_t *)keys_ram;
    const amiibo_master_key_t *tag_key = (const amiibo_master_key_t *)(keys_ram + 80);
    const uint8_t *xorpad = keys_ram + 128;  // Fixed: was 160, should be 128

    // Extract tag metadata
    const uint8_t *write_counter = &tag_data[AMIIBO_OFFSET_WRITE_COUNTER];
    const uint8_t *keygen_salt = &tag_data[AMIIBO_OFFSET_KEYGEN_SALT];
    const uint8_t *model_info = &tag_data[AMIIBO_OFFSET_MODEL_INFO];

    // Step 1: Decrypt with old UID
    amiibo_derived_keys_t old_data_keys;
    if (!derive_keys(data_key, old_uid, write_counter, keygen_salt, xorpad, true, &old_data_keys)) {
        NRF_LOG_ERROR("Failed to derive keys");
        return false;
    }

    // Decrypt encrypted data parts with continuous counter
    uint8_t decrypted[AMIIBO_ENCRYPTED_DATA_SIZE];
    if (!aes_ctr_crypt_amiibo_data(old_data_keys.aes_key, old_data_keys.aes_iv,
                                   &tag_data[AMIIBO_OFFSET_ENCRYPTED_PART1],
                                   AMIIBO_OFFSET_ENCRYPTED_PART1_SIZE,
                                   &tag_data[AMIIBO_OFFSET_ENCRYPTED_PART2],
                                   AMIIBO_OFFSET_ENCRYPTED_PART2_SIZE,
                                   decrypted,
                                   &decrypted[AMIIBO_OFFSET_ENCRYPTED_PART1_SIZE])) {
        NRF_LOG_ERROR("Decryption failed");
        return false;
    }

    // Step 2: Compute new Tag HMAC with new UID
    amiibo_derived_keys_t new_tag_keys;
    if (!derive_keys(tag_key, new_uid, write_counter, keygen_salt, xorpad, true, &new_tag_keys)) {
        NRF_LOG_ERROR("Failed to derive keys");
        return false;
    }

    // Tag HMAC input: new_uid[0:8] + model_info + keygen_salt
    uint8_t tag_hmac_input[8 + AMIIBO_MODEL_INFO_SIZE + AMIIBO_KEYGEN_SALT_SIZE];
    memcpy(&tag_hmac_input[0], new_uid, 8);
    memcpy(&tag_hmac_input[8], model_info, AMIIBO_MODEL_INFO_SIZE);
    memcpy(&tag_hmac_input[8 + AMIIBO_MODEL_INFO_SIZE], keygen_salt, AMIIBO_KEYGEN_SALT_SIZE);

    uint8_t new_tag_hmac[32];
    if (!hmac_sha256(new_tag_keys.hmac_key, 16, tag_hmac_input, sizeof(tag_hmac_input), new_tag_hmac)) {
        NRF_LOG_ERROR("HMAC computation failed");
        return false;
    }

    // Update Tag HMAC in tag data
    memcpy(&tag_data[AMIIBO_OFFSET_TAG_HMAC], new_tag_hmac, AMIIBO_HMAC_SIZE);

    // Step 3: Compute new Data HMAC over DECRYPTED data with new UID
    amiibo_derived_keys_t new_data_keys;
    if (!derive_keys(data_key, new_uid, write_counter, keygen_salt, xorpad, true, &new_data_keys)) {
        NRF_LOG_ERROR("Failed to derive keys");
        return false;
    }

    // Build temporary buffer with decrypted sections for HMAC computation
    // CRITICAL: Data HMAC is computed over DECRYPTED data!
    uint8_t temp_data[540];
    memcpy(temp_data, tag_data, 540);
    memcpy(&temp_data[AMIIBO_OFFSET_ENCRYPTED_PART1], decrypted, AMIIBO_OFFSET_ENCRYPTED_PART1_SIZE);
    memcpy(&temp_data[AMIIBO_OFFSET_ENCRYPTED_PART2], &decrypted[AMIIBO_OFFSET_ENCRYPTED_PART1_SIZE], AMIIBO_OFFSET_ENCRYPTED_PART2_SIZE);

    // Update UID in temp data
    memcpy(&temp_data[AMIIBO_OFFSET_UID], new_uid, 8);

    // Data HMAC input: settings[17:52] + decrypted[160:520] + tag_hmac + new_uid + model_salt[84:128]
    uint8_t data_hmac_input[479];
    uint16_t offset = 0;

    memcpy(&data_hmac_input[offset], &temp_data[17], 35);  // Settings with decrypted 20-52
    offset += 35;
    memcpy(&data_hmac_input[offset], &temp_data[160], 360);  // Decrypted part 2
    offset += 360;
    memcpy(&data_hmac_input[offset], new_tag_hmac, 32);  // New Tag HMAC
    offset += 32;
    memcpy(&data_hmac_input[offset], new_uid, 8);  // New UID
    offset += 8;
    memcpy(&data_hmac_input[offset], &temp_data[84], 44);  // Model info + salt
    offset += 44;

    uint8_t new_data_hmac[32];
    if (!hmac_sha256(new_data_keys.hmac_key, 16, data_hmac_input, sizeof(data_hmac_input), new_data_hmac)) {
        NRF_LOG_ERROR("HMAC computation failed");
        return false;
    }

    // Update Data HMAC in tag data
    memcpy(&tag_data[AMIIBO_OFFSET_DATA_HMAC], new_data_hmac, AMIIBO_HMAC_SIZE);

    // Update UID in tag data
    memcpy(&tag_data[AMIIBO_OFFSET_UID], new_uid, 8);

    // Update BCC1 at byte 8
    tag_data[8] = new_uid[4] ^ new_uid[5] ^ new_uid[6] ^ new_uid[7];

    // Update password (PWD) and PACK based on new UID
    // PWD is at page 133 (bytes 532-535), PACK is at page 134 (bytes 536-537)
    // Extract 7-byte UID from 8-byte UID (skip BCC0 at index 3)
    uint8_t uid_7byte[7];
    uid_7byte[0] = new_uid[0];
    uid_7byte[1] = new_uid[1];
    uid_7byte[2] = new_uid[2];
    uid_7byte[3] = new_uid[4];  // Skip BCC0 at new_uid[3]
    uid_7byte[4] = new_uid[5];
    uid_7byte[5] = new_uid[6];
    uid_7byte[6] = new_uid[7];

    // Generate PWD from UID
    tag_data[532] = 0xAA ^ uid_7byte[1] ^ uid_7byte[3];
    tag_data[533] = 0x55 ^ uid_7byte[2] ^ uid_7byte[4];
    tag_data[534] = 0xAA ^ uid_7byte[3] ^ uid_7byte[5];
    tag_data[535] = 0x55 ^ uid_7byte[4] ^ uid_7byte[6];

    // PACK is always 0x8080 for Amiibo
    tag_data[536] = 0x80;
    tag_data[537] = 0x80;

    // Step 4: Re-encrypt with new UID using continuous counter
    if (!aes_ctr_crypt_amiibo_data(new_data_keys.aes_key, new_data_keys.aes_iv,
                                   decrypted,
                                   AMIIBO_OFFSET_ENCRYPTED_PART1_SIZE,
                                   &decrypted[AMIIBO_OFFSET_ENCRYPTED_PART1_SIZE],
                                   AMIIBO_OFFSET_ENCRYPTED_PART2_SIZE,
                                   &tag_data[AMIIBO_OFFSET_ENCRYPTED_PART1],
                                   &tag_data[AMIIBO_OFFSET_ENCRYPTED_PART2])) {
        NRF_LOG_ERROR("Re-encryption failed");
        return false;
    }

    return true;
}
