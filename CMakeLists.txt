cmake_minimum_required(VERSION 3.13)
# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
include(pico_sdk_import.cmake)

project(rp2350_hacking_challenge_2)
 
pico_sdk_init()

add_executable(rp2350_hacking_challenge_2)

target_compile_definitions(rp2350_hacking_challenge_2 PRIVATE
        # The following are to reduce the size of the binary
        
        RC_COUNT=0
        HARDENING=0
        DOUBLE_HARDENING=0

        INLINE_REF_ROUNDKEY_SHARES_S=1
        INLINE_REF_ROUNDKEY_HVPERMS_S=1
        INLINE_SHIFT_ROWS_S=1
        INLINE_MAP_SBOX_S=1

        CALLER_INIT_RCP_COUNT=1
)
target_include_directories(rp2350_hacking_challenge_2 PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_sources(rp2350_hacking_challenge_2 PRIVATE rp2350_hacking_challenge_2.c aes.S)
#pico_set_binary_type(rp2350_hacking_challenge_2 no_flash)
target_link_libraries(rp2350_hacking_challenge_2 PRIVATE
        pico_stdlib
        hardware_pio
        )

pico_add_extra_outputs(rp2350_hacking_challenge_2)



# enable usb output, disable uart output
pico_enable_stdio_usb(rp2350_hacking_challenge_2 1)
pico_enable_stdio_uart(rp2350_hacking_challenge_2 0)
