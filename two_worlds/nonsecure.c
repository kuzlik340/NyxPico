#include <stdio.h>
#include "pico/bootrom.h"
#include "hardware/clocks.h"
#include "pico/stdlib.h"

#include "secure_call_user_callbacks.h"

int main() {
    // Request user IRQ from secure, which stdio_usb will use
    user_irq_request_unused_from_secure(1);

    // Start stdio_usb
    stdio_usb_init();

    for (int i=0; i < 10; i++) {
        printf("Asking for secret\n");
        int value = rom_secure_call(0, 0, 0, 0, SECURE_CALL_RETURN_SECRET);
        printf("Secret is %d\n", value);
        sleep_ms(1000);
    }

    // Demonstrate triggering a secure fault, by reading secure memory at start of SRAM
    //printf("Triggering secure fault by reading secure memory\n");
    //volatile uint32_t thing = *(uint32_t*)SRAM_BASE;
    //printf("Some secure memory is %08x\n", thing);

    return 0;
}
