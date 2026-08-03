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
#include <string.h>

static uint8_t s_private_key[32];
static uint8_t s_public_key[64];
static bool s_have_keypair = false;
static uint8_t s_session_key[32];
static bool s_have_session = false;

static int trng_rng_function(uint8_t *dest, unsigned size) {
    //printf("TRNG was called\n");
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
    //printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        //printf("%02x", buf[i]);
    }
    //printf("\n");
}

bool secure_generate_keypair(void) {
    int ok = uECC_make_key(s_public_key, s_private_key, uECC_secp256r1());
    if (ok) {
        s_have_keypair = true;
    }
    return ok;
}

int return_pub_key(uint32_t a){
    uint8_t *ns_pubkey_out = (uint8_t *)a;

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

int ecdh_compute(uint32_t a, uint32_t b) {
    uint8_t *ns_peer_pub = (uint8_t *)a;
#ifdef DEBUG
    uint8_t *out_secret = (uint8_t *)b;
#endif
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
    memcpy(out_secret, s_session_key, 32); 
    return 0;
}

int secure_call_user_callback(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t fn) {
    switch (fn) {
    case SECURE_CALL_RETURN_PUBKEY: {
        return return_pub_key(a);
    }
    case SECURE_CALL_ECDH_COMPUTE: {
        return ecdh_compute(a, b); 
    }
    default:
        return BOOTROM_ERROR_INVALID_ARG;
    }
}

int main()
{
    stdio_init_all();

    // If this was a watchdog reboot, reset to USB boot
    if (watchdog_enable_caused_reboot()) {
        //printf("This was a watchdog reboot - resetting\n");
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
    //printf("Boot partition: %d\n", info.partition);

    // Roll QMI to matching Non-Secure partition, as Non-Secure runs from XIP
    int ns_partition = rom_get_owned_partition(info.partition);
    //printf("Matching Non-Secure partition: %d\n", ns_partition);
    int rc = rom_roll_qmi_to_partition(ns_partition);
    //printf("Rolled QMI to Non-Secure partition, rc=%d\n", rc);

    // Configure SAU regions
    secure_sau_configure_split();

    // Enable SAU
    secure_sau_set_enabled(true);
    //printf("SAU Configured & Enabled\n");

    // Install default hardfault handler, with callback to reset to USB boot
    secure_install_default_hardfault_handler(hardfault_callback);

    // Launch Non-Secure binary
    secure_launch_nonsecure_binary_default();

    // Should never return from non-secure code
    //printf("Shouldn't return from non-secure code\n");
}
