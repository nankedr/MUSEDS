#ifndef HASH_H_INCLUDED
#define HASH_H_INCLUDED

#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <stdint.h>
//H1用sha256实现
void H_1(uint8_t *digest, const uint8_t *message, size_t len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
}
void H_2(uint8_t *digest, const uint8_t *message, size_t len) {
    SHA256_CTX ctx;
    SHA224_Init(&ctx);
    SHA224_Update(&ctx, message, len);
    SHA224_Final(digest, &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
}


void H_3(uint8_t *digest, const uint8_t *message, size_t len) {
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, message, len);
    SHA512_Final(digest, &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
}


void H(uint8_t *digest, const uint8_t *message, size_t len) {
    H_1(digest, message, len);
}
#endif // HASH_H_INCLUDED
