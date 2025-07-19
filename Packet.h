#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/types.h>
#endif

#define MAX_PAYLOAD_SIZE 256
#define MAX_ROUTE_LEN 8
#define NONCE_BYTES 12

typedef struct {
    uint32_t message_id;
    uint16_t seq;
    uint16_t total;
    uint8_t sender_id;
    uint8_t hop_count;
    uint8_t hop_index;
    uint8_t route[MAX_ROUTE_LEN];
    uint8_t nonce[NONCE_BYTES];
    uint16_t payload_len;
    uint8_t encrypted[MAX_PAYLOAD_SIZE];
} EncryptedPacket;

ssize_t create_encrypted_packets(const uint8_t* msg, size_t msg_len,
    const uint8_t key[32], uint32_t message_id,
    EncryptedPacket* packets, size_t max_packets,
    uint8_t sender_id, const uint8_t* route, uint8_t hop_count);

int decrypt_packet(const EncryptedPacket* packet,
    const uint8_t key[32], uint8_t* out_buf, size_t out_max);

#endif
