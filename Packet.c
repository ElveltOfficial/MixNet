#include "Packet.h"
#include "Crypto.h"
#include <string.h>
#include <sodium.h>

ssize_t create_encrypted_packets(const uint8_t* msg, size_t msg_len,
    const uint8_t key[32], uint32_t message_id,
    EncryptedPacket* packets, size_t max_packets,
    uint8_t sender_id, const uint8_t* route, uint8_t hop_count) {

    ssize_t total = (msg_len + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;
    if (total > max_packets) return -1;

    for (ssize_t i = 0; i < total; ++i) {
        size_t offset = i * MAX_PAYLOAD_SIZE;
        size_t chunk_size = (msg_len - offset > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : (msg_len - offset);

        EncryptedPacket* p = &packets[i];
        p->message_id = message_id;
        p->seq = (uint16_t)i;
        p->total = (uint16_t)total;
        p->sender_id = sender_id;
        p->hop_count = hop_count;
        p->hop_index = 0;
        memset(p->route, 0, MAX_ROUTE_LEN);
        memcpy(p->route, route, hop_count * sizeof(uint8_t));
        randombytes_buf(p->nonce, NONCE_BYTES);
        chacha20_encrypt(p->encrypted, msg + offset, chunk_size, key, p->nonce);
        p->payload_len = (uint16_t)chunk_size;
    }
    sodium_memzero((void*)key, 32);
    return total;
}

int decrypt_packet(const EncryptedPacket* packet,
    const uint8_t key[32], uint8_t* out_buf, size_t out_max) {

    size_t decrypt_len = packet->payload_len;
    if (decrypt_len > out_max) decrypt_len = out_max;

    int ret = chacha20_decrypt(out_buf, packet->encrypted, decrypt_len, key, packet->nonce);
    sodium_memzero((void*)key, 32);
    if (ret != 0) return -1;
    return (int)decrypt_len;
}
