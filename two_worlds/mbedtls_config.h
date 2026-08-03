#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// Minimal config: just what HKDF needs, plus AES-GCM for the encrypt/decrypt
// step coming next. Trim further later if flash size becomes a concern.

#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C

// For the upcoming AES-GCM encrypt/decrypt step:
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C

#endif /* MBEDTLS_CONFIG_H */