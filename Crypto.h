#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <sodium.h>

#define PRIVATE_KEY_BYTES 32
#define PUBLIC_KEY_BYTES 32
#define SHARED_KEY_BYTES 32
#define NONCE_BYTES 12

int crypto_init();

int generate_keypair(uint8_t public_key[PUBLIC_KEY_BYTES], uint8_t private_key[PRIVATE_KEY_BYTES]);

int generate_shared_key(uint8_t shared_key[SHARED_KEY_BYTES],
    const uint8_t my_private[PRIVATE_KEY_BYTES],
    const uint8_t their_public[PUBLIC_KEY_BYTES]);

int chacha20_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len,
    const uint8_t key[SHARED_KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES]);

int chacha20_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len,
    const uint8_t key[SHARED_KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES]);

#endif
