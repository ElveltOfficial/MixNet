#include "Crypto.h"
#include <string.h>

int crypto_init() {
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}

int generate_keypair(uint8_t public_key[PUBLIC_KEY_BYTES], uint8_t private_key[PRIVATE_KEY_BYTES]) {
    return crypto_box_keypair(public_key, private_key);
}

int generate_shared_key(uint8_t shared_key[SHARED_KEY_BYTES],
    const uint8_t my_private[PRIVATE_KEY_BYTES],
    const uint8_t their_public[PUBLIC_KEY_BYTES]) {
    return crypto_scalarmult(shared_key, my_private, their_public);
}

int chacha20_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len,
    const uint8_t key[SHARED_KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES]) {
    return crypto_stream_chacha20_xor(ciphertext, plaintext, len, nonce, key);
}

int chacha20_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len,
    const uint8_t key[SHARED_KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES]) {
    return crypto_stream_chacha20_xor(plaintext, ciphertext, len, nonce, key);
}
