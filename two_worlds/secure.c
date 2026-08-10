#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include "hardware/watchdog.h"
#include "pico/secure.h"
#include "arm_cmse.h"
#include "secure_call_user_callbacks.h"
#include "uECC.h"
#include "pico/rand.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/chachapoly.h"
#include <string.h>

#define NYX_CURVE uECC_secp256r1()

static uint8_t s_private_key[32];
static uint8_t s_public_key[64];
static bool s_have_keypair = false;
static uint8_t s_session_key[32];
static bool s_have_session = false;
static uint64_t s_send_counter = 0;

static int trng_rng_function(uint8_t *dest, unsigned size) {
    printf("TRNG was called\n");
    while (size >= 4) {
        uint32_t r = get_rand_32();
        memcpy(dest, &r, 4);
        dest += 4; size -= 4;
    }
    if (size) {
        uint32_t r = get_rand_32();
        memcpy(dest, &r, size);
    }
    return 1; // success
}

bool repeating_timer_callback(__unused struct repeating_timer *t) {
    watchdog_update();
    return true;
}

void hardfault_callback(void) {
    if (m33_hw->dhcsr & M33_DHCSR_C_DEBUGEN_BITS) {
        // If in debug mode, breakpoint
        __breakpoint();
    } else {
        // If not in debug mode, reset to USB boot
        rom_reset_usb_boot(0, 0);
    }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

bool secure_generate_keypair(void) {
    int ok = uECC_make_key(s_public_key, s_private_key, uECC_secp256r1());
    if (ok) {
        s_have_keypair = true;
    }
    return ok;
}

static void make_nonce(uint8_t nonce[12]) {
    memset(nonce, 0, 12);
    memcpy(nonce + 4, &s_send_counter, 8);
}

int encrypt_msg(uint8_t *pt_in, uint32_t len, uint8_t *ct_out) {
    printf("Encrypt was called");
    if (!cmse_check_address_range(pt_in, len, CMSE_NONSECURE)) return -1;
    if (!cmse_check_address_range(ct_out, len + 16, CMSE_NONSECURE)) return -1;
    if (!s_have_session) return -3;
    if (len > 256) return -5;

    uint8_t pt_local[256];
    memcpy(pt_local, pt_in, len);

    uint8_t nonce[12];
    make_nonce(nonce);

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_setkey(&ctx, s_session_key);

    uint8_t ct_local[256];
    uint8_t tag[16];
    int rc = mbedtls_chachapoly_encrypt_and_tag(&ctx, len, nonce,
                                                  NULL, 0, // no additional authenticated data
                                                  pt_local, ct_local, tag);

    mbedtls_chachapoly_free(&ctx);
    memset(pt_local, 0, sizeof(pt_local));
    
    if (rc != 0) return -6;

    memcpy(ct_out, nonce, 12);
    memcpy(ct_out + sizeof(nonce), ct_local, sizeof(ct_local));
    memcpy(ct_out + sizeof(nonce) + len, tag, sizeof(tag));

    s_send_counter++;
    printf("\n Encryption done");
    return 0;
}

int decrypt_msg(uint8_t *ct_in, uint32_t len, uint8_t *pt_out) {
    if (len < 28) return -5;
    uint32_t ct_len = len - 12 - 16;
    
    if (!cmse_check_address_range(ct_in, len, CMSE_NONSECURE)) return -1;
    if (!cmse_check_address_range(pt_out, ct_len, CMSE_NONSECURE)) return -1;
    if (!s_have_session) return -3;

    uint8_t local_buf[288];
    memcpy(local_buf, ct_in, len);

    uint8_t *nonce = local_buf;
    uint8_t *ciphertext = local_buf + 12;
    uint8_t *tag = local_buf + 12 + ct_len;

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_setkey(&ctx, s_session_key);

    uint8_t pt_local[256];
    int rc = mbedtls_chachapoly_auth_decrypt(&ctx, ct_len, nonce,
                                               NULL, 0,
                                               tag, ciphertext, pt_local);
    mbedtls_chachapoly_free(&ctx);

    if (rc != 0) {
        printf("Decrypt failed: auth tag mismatch (tampered or wrong key)\n");
        memset(pt_local, 0, sizeof(pt_local));
        return -7;
    }
    pt_out[(len - 12 - 16)] = '\0';
    memcpy(pt_out, pt_local, ct_len);
    memset(pt_local, 0, sizeof(pt_local));
    return 0;
}

int return_pub_key(uint8_t *ns_pubkey_out){

    // Validate: this pointer must genuinely belong to non-secure memory,
    // and the caller must be allowed to write 64 bytes there
    if (!cmse_check_address_range(ns_pubkey_out, 64, CMSE_NONSECURE)) {
        printf("Rejected: bad NS pointer\n");
        return -1;
    }

    if (!secure_generate_keypair()) {
        return -2;
    }

    memcpy(ns_pubkey_out, s_public_key, 64);
    return 0; // success
}

int ecdh_compute(uint8_t *ns_peer_pub) {

    if (!cmse_check_address_range(ns_peer_pub, 64, CMSE_NONSECURE)) {
        printf("Rejected: bad NS pointer\n");
        return -1;
    }
    if (!s_have_keypair) {
        printf("No local keypair yet\n");
        return -3;
    }

    uint8_t peer_pub_local[64];
    memcpy(peer_pub_local, ns_peer_pub, 64); // copy out before use

    uint8_t raw_secret[32];
    if (!uECC_shared_secret(peer_pub_local, s_private_key, raw_secret, uECC_secp256r1())) {
        printf("ECDH failed\n");
        return -4;
    }

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hkdf(md,
        NULL, 0,
        raw_secret, 32,
        (const unsigned char *)"nyxpico-session-v1", 19,
        s_session_key, 32);

    memset(raw_secret, 0, sizeof(raw_secret)); // zero the raw ECDH output

    s_have_session = true;
    printf("Session key derived\n");

    // print a short fingerprint only — never the full session key
    uint8_t fp[4];
    memcpy(fp, s_session_key, 4);
    print_hex("Session fingerprint", fp, 4);
    s_send_counter = 0;
    return 0;
}

int secure_call_user_callback(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t fn) {
    switch (fn) {
    case RETURN_PUBKEY: {
        return return_pub_key((uint8_t *)a);
    }
    case ECDH_COMPUTE: {
        return ecdh_compute((uint8_t *)a); 
    }
    case ENCRYPT_MESSAGE: {
        return encrypt_msg((uint8_t *)a, b, (uint8_t *)c);
    }
    case DECRYPT_MESSAGE: {
        return decrypt_msg((uint8_t *)a, b, (uint8_t *)c);
    }
    default:
        return BOOTROM_ERROR_INVALID_ARG;
    }
}

int main()
{
    stdio_init_all();
    
    // Wait 5 seconds so the user could connect to the board via serial connection
    sleep_ms(3000);
    // If this was a watchdog reboot, reset to USB boot
    if (watchdog_enable_caused_reboot()) {
        printf("This was a watchdog reboot - resetting\n");
        rom_reset_usb_boot(0, 0);
    }
    // Setting onboard TRNG as source of randomness
    uECC_set_rng(trng_rng_function);
    // Create a repeating timer to update the watchdog every 1000ms
    struct repeating_timer timer;
    watchdog_enable(1100, true);
    add_repeating_timer_ms(-1000, repeating_timer_callback, NULL, &timer);

    // Create user callback
    rom_secure_call_add_user_callback(secure_call_user_callback, SECURE_CALL_CALLBACKS_MASK);

    // Get boot partition
    boot_info_t info;
    rom_get_boot_info(&info);
    printf("Boot partition: %d\n", info.partition);

    // Roll QMI to matching Non-Secure partition, as Non-Secure runs from XIP
    int ns_partition = rom_get_owned_partition(info.partition);
    printf("Matching Non-Secure partition: %d\n", ns_partition);
    int rc = rom_roll_qmi_to_partition(ns_partition);
    printf("Rolled QMI to Non-Secure partition, rc=%d\n", rc);

    // Configure SAU regions
    secure_sau_configure_split();

    // Enable SAU
    secure_sau_set_enabled(true);
    printf("SAU Configured & Enabled\n");

    // Install default hardfault handler, with callback to reset to USB boot
    secure_install_default_hardfault_handler(hardfault_callback);

    // Launch Non-Secure binary
    secure_launch_nonsecure_binary_default();

    // Should never return from non-secure code
    printf("Shouldn't return from non-secure code\n");
}
