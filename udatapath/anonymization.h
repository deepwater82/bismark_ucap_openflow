#ifndef _BISMARK_PASSIVE_ANONYMIZATION_H_
#define _BISMARK_PASSIVE_ANONYMIZATION_H_

#include <stdint.h>
#include <net/ethernet.h>

#define ANONYMIZATION_DIGEST_LENGTH 20

/* Must call exactly once per process, before any anonymization is performed. */
int anonymization_init(void);

/* Anonymize the lower 24 bits of a MAC address into the provided buffer. The
 * digest buffer must be at least ANONYMIZATION_DIGEST_LENGTH bytes long. */
void anonymize_mac(const uint8_t mac[ETH_ALEN], uint8_t digest[ETH_ALEN]);

/* Deanonymize the lower 24 bits of the MAC  address into the provided buffer.
 * This only works if the address had been previously anonymized with
 * anonymize_mac during the runtime of this program. */
int deanonymize_mac(const uint8_t mac[ETH_ALEN], uint8_t digest[ETH_ALEN]);

#endif
