#include <stdio.h>
#include "pico/bootrom.h"
#include "hardware/clocks.h"
#include "pico/stdlib.h"
#include <string.h>
#include "secure_call_user_callbacks.h"


static const char *logo = {
"\n"
"88b 88  Yb  dP  Yb  dP  8888Yb  88   dPoob8   dP8Yb  \n"
"88Yb88   YbdP    YbdP   88__dP  88  dP   `o  dP   Yb \n"
"88 Y88    8P     dPYb   88888   88  Yb       Yb   dP \n"
"88  Y8   dP     dP  Yb  88      88   YboodP   YbodP  \n"
"\n"
"Your privacy matters.\n\n\n"
};

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static bool parse_hex(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) return false; // TODO fix !=
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        out[i] = (uint8_t)byte;
    }
    return true;
}

static void read_line_echo(char *buf, size_t buf_size) {
    size_t i = 0;
    while (i < buf_size - 1) {
        int c = getchar(); // blocks until a character arrives
        if (c == '\r' || c == '\n') {
            putchar('\n');
            break;
        }
        if ((c == '\b' || c == 0x7f) && i > 0) { // backspace/DEL
            i--;
            printf("\b \b"); // erase the character visually
            continue;
        }
        if (c < 0x20 || c > 0x7e) {
            continue; // ignore other control/non-printable characters
        }
        putchar(c);   // echo it
        buf[i++] = (char)c;
    }
    buf[i] = '\0'; // TODO Could be out of address?
}

static void print_error(const char *message, int rc){
    printf("ERROR: ");
    printf("%s", message);
    printf("rc=%d\n", rc);
}

int main() {
    // Request user IRQ from secure, which stdio_usb will use
    user_irq_request_unused_from_secure(1);

    // Start stdio_usb
    stdio_usb_init();
    sleep_ms(3000);
    printf("%s", logo);
    // Obtain and display public key
    uint8_t public_key[64];
    int rc = rom_secure_call((uint32_t)public_key, 0, 0, 0, RETURN_PUBKEY);
    if (rc == 0) {
        print_hex("Public key", public_key, sizeof(public_key));
    } else {
        print_error("RETURN_PUBKEY failed", rc);
        return 1;
    }

    while(1) {
        // Wait for user to input peer's public key to start ECDH
        printf("\nInsert peer public key: ");
        char line[130];
        read_line_echo(line, sizeof(line));
        // Strip trailing newline
        line[strcspn(line, "\r\n")] = 0; 
        
        uint8_t peer_pubkey[64];
        if (!parse_hex(line, peer_pubkey, 64)) {
            printf("Invalid input, expected 128 hex chars\n");
            continue;
        } 
        else {
            int rc = rom_secure_call((uint32_t)peer_pubkey, 0, 0, 0, ECDH_COMPUTE);
            if (rc == 0) {
                printf("ECDH compute successful, you can start chatting");
                break;
            }
            else{
                print_error("ECDH_COMPUTE failed", rc);
                return 1;
            }
        }
    }

    while(1) {
        printf("\nYou can now start chatting using DEC to decrypt and ENC to encrypt\n\n\n");
        char line[259] = {0};
        read_line_echo(line, sizeof(line));
        line[strcspn(line, "\r\n")] = 0; 
        char command[4];
        memcpy(command, line, 3);
        command[3] = '\0';
        char out_buf[300] = {0};

        if(!strcmp(command, "DEC")){
            uint8_t enc_bytes[250] = {0};
            size_t byte_length =  (strlen(line) - 4) / 2;
            parse_hex((line + 4), enc_bytes, byte_length);
            print_hex("DBG: ", enc_bytes, byte_length);
            int rc = rom_secure_call((uint32_t)enc_bytes, byte_length, (uint32_t)out_buf, 0, DECRYPT_MESSAGE);
            printf("DEC Message: %s and return code is %d", out_buf, rc);
        }
        else if(!strcmp(command, "ENC")){
            size_t len = strlen(line) - 4;
            printf("Plain text len = %d\n", len);
            int rc = rom_secure_call((uint32_t)(line + 4), strlen(line) - 4, (uint32_t)out_buf, 0, ENCRYPT_MESSAGE);
            print_hex("ENC Message: ", (uint8_t *)out_buf, (strlen(line) - 4 + 12 + 16));
            printf(" and return code is %d", rc);
        }
        else if(!strcmp(command, "EXI")){
            break;
        }
        else{
            printf("\nUnknown command\n");
        }
    }

    
    return 0;
}
