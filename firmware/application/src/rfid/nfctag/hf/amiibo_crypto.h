#ifndef AMIIBO_CRYPTO_H
#define AMIIBO_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>

// Amiibo encryption/decryption constants
#define AMIIBO_UID_SIZE 8
#define AMIIBO_WRITE_COUNTER_SIZE 2
#define AMIIBO_KEYGEN_SALT_SIZE 32
#define AMIIBO_ENCRYPTED_DATA_SIZE 392
#define AMIIBO_HMAC_SIZE 32
#define AMIIBO_AES_KEY_SIZE 16
#define AMIIBO_MODEL_INFO_SIZE 12

// Offsets in NTAG215 memory
#define AMIIBO_OFFSET_UID 0
#define AMIIBO_OFFSET_WRITE_COUNTER 17
#define AMIIBO_OFFSET_ENCRYPTED_PART1 20
#define AMIIBO_OFFSET_ENCRYPTED_PART1_SIZE 32
#define AMIIBO_OFFSET_TAG_HMAC 52
#define AMIIBO_OFFSET_MODEL_INFO 84
#define AMIIBO_OFFSET_KEYGEN_SALT 96
#define AMIIBO_OFFSET_DATA_HMAC 128
#define AMIIBO_OFFSET_ENCRYPTED_PART2 160
#define AMIIBO_OFFSET_ENCRYPTED_PART2_SIZE 360

/**
 * Re-encrypt Amiibo data with a new UID
 * This function:
 * 1. Decrypts the encrypted sections using the old UID
 * 2. Recalculates Tag HMAC with new UID
 * 3. Recalculates Data HMAC over decrypted data with new UID
 * 4. Re-encrypts the data with the new UID
 *
 * @param tag_data Pointer to the full NTAG215 data (540 bytes)
 * @param new_uid Pointer to the new 8-byte UID
 * @param old_uid Pointer to the old 8-byte UID
 * @param keys Pointer to the master keys (160 bytes)
 * @return true if successful, false on error
 */
bool amiibo_reencrypt_with_new_uid(uint8_t *tag_data, const uint8_t *new_uid, const uint8_t *old_uid, const uint8_t *keys);

/**
 * Check if tag data appears to be a valid Amiibo
 * Checks for proper NTAG215 structure and Amiibo-specific patterns
 *
 * @param tag_data Pointer to the tag data
 * @return true if appears to be Amiibo, false otherwise
 */
bool amiibo_is_valid(const uint8_t *tag_data);

#endif // AMIIBO_CRYPTO_H
