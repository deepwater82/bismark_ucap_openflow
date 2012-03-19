#include "anonymization.h"

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"
#include "util.h"

#define ANONYMIZATION_SEED_FILE "/etc/bismark/passive.key"
#define ANONYMIZATION_SEED_LEN 16
#define DIGEST_TABLE_LEN 256

static uint8_t seed[ANONYMIZATION_SEED_LEN];
static char seed_hex_digest[ANONYMIZATION_DIGEST_LENGTH * 2 + 1];
static int initialized = 0;

typedef struct {
    uint8_t mac[ETH_ALEN];
    uint8_t digest[ETH_ALEN];
} digest_table_entry_t;

static digest_table_entry_t digest_table[DIGEST_TABLE_LEN];
static int digest_table_index;
static int digest_table_length;

/* Anonymize a buffer of given length. Places the resulting digest into the
 * provided digest buffer, which must be at least ANONYMIZATION_DIGEST_LENGTH
 * bytes long. */
static void anonymization_process(const uint8_t* const data,
        const int len,
        unsigned char* const digest) {
    assert(initialized);
    sha1_hmac(seed, ANONYMIZATION_SEED_LEN, data, len, digest);
}

static int init_hex_seed_digest(void) {
    unsigned char seed_digest[ANONYMIZATION_DIGEST_LENGTH];
    char* hex_digest;
    anonymization_process(seed, ANONYMIZATION_SEED_LEN, seed_digest);
    hex_digest = (char*)buffer_to_hex(seed_digest, ANONYMIZATION_DIGEST_LENGTH);
    if (!hex_digest) {
        return -1;
    }
    memcpy(seed_hex_digest, hex_digest, sizeof(seed_hex_digest));
    seed_hex_digest[sizeof(seed_hex_digest) - 1] = '\0';
    return 0;
}

int anonymization_init(void) {
    FILE* handle = fopen(ANONYMIZATION_SEED_FILE, "rb");
    if (!handle) {
        perror("Error opening seed file");
        return -1;
    }
    if (fread(seed, 1, ANONYMIZATION_SEED_LEN, handle) < ANONYMIZATION_SEED_LEN) {
        perror("Error reading seed file");
        fclose(handle);
        return -1;
    }

    initialized = 1;

    if (init_hex_seed_digest()) {
        initialized = 0;
        return -1;
    }

    digest_table_index = 0;
    digest_table_length = 0;

    return 0;
}

void anonymize_mac(const uint8_t mac[ETH_ALEN], uint8_t digest[ETH_ALEN]) {
    unsigned char mac_digest[ANONYMIZATION_DIGEST_LENGTH];

    memcpy(digest_table[digest_table_index].mac, mac, ETH_ALEN);
    anonymization_process(mac, ETH_ALEN, mac_digest);
    memcpy(digest, mac_digest, ETH_ALEN);
    memcpy(mac_digest, mac, ETH_ALEN / 2);
    memcpy(digest_table[digest_table_index].digest, digest, ETH_ALEN);

    digest_table_index = (digest_table_index + 1) % DIGEST_TABLE_LEN;
    if (digest_table_length < DIGEST_TABLE_LEN) {
        ++digest_table_length;
    }

    fprintf(stderr, "SEED_digest: %s\n", seed_hex_digest);

}

int deanonymize_mac(const uint8_t digest[ETH_ALEN], uint8_t mac[ETH_ALEN]) {
    int idx;
    for (idx = 0; idx < digest_table_length; ++idx) {
        if (memcmp(digest, digest_table[idx].digest, ETH_ALEN) == 0) {
            memcpy(mac, digest_table[idx].mac, ETH_ALEN);
            return 0;
        }
    }
    return -1;
}
