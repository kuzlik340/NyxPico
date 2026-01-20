# Add secure executable
add_executable(secure secure.c)
target_link_libraries(secure
        pico_stdlib
        hardware_watchdog
        pico_secure
)

# Packaged no_flash binary
pico_set_binary_type(secure no_flash)
pico_package_uf2_output(secure 0x10000000)
pico_add_extra_outputs(secure)

# Add non-secure executable
add_executable(nonsecure nonsecure.c)
target_link_libraries(nonsecure
        pico_stdlib
)

# Set UF2 family manually
pico_set_uf2_family(nonsecure "rp2350-arm-ns")

# Use stdio_usb
pico_enable_stdio_uart(nonsecure 0)
pico_enable_stdio_usb(nonsecure 1)

# Default flash binary
pico_add_extra_outputs(nonsecure)

# Set security options
pico_set_security_options(secure nonsecure
    USER_IRQ USB
    NONSECURE_TIMER 1
)

# Set security ram split
pico_set_security_ram_split(secure nonsecure SIMPLE 64k 2k)

# Create combined UF2, for loading into the partition table (non-secure first)
pico_concatenate_uf2_outputs(two_worlds nonsecure secure)