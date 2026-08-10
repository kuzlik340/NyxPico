#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// Minimal config: just what HKDF needs, plus AES-GCM for the encrypt/decrypt
// step coming next. Trim further later if flash size becomes a concern.

#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C

// For the encrypt/decrypt procdures
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

#define MBEDTLS_B
#endif /* MBEDTLS_CONFIG_H */