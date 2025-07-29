#include "pico/stdlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Trigger pin is 13
#define TRIGGER 13

extern void decrypt(uint8_t* key4way, uint8_t* IV_OTPsalt, uint8_t* IV_public, uint8_t(*buf)[32], int nblk);

void readuart(char *destination, size_t length) {
    for(int i=0; i < length; i++) {
        destination[i] = getchar();
    }
}

char scratch_backup[2048];


void trigger() {
    gpio_put(TRIGGER, 1);
    __asm("NOP; NOP; NOP; NOP; NOP; NOP; NOP; NOP; ");
    gpio_put(TRIGGER, 0);
}

int main() {
    // You can adjust the stdio target in CMakeLists.txt if you want to disable USB
    stdio_init_all();
    // stdio_uart_init_full (uart0, 115200, 14, 15);

    gpio_init(TRIGGER);
    gpio_set_dir(TRIGGER, GPIO_OUT);
    gpio_put(TRIGGER, 0);

    uint32_t scratch_addr = 0x20081000;
    uint32_t *scratch_ptr = (uint32_t*)scratch_addr;

    // Backup scratch-memory
    memcpy(scratch_backup, scratch_ptr, 2048);

    // Default key will decode to 00000...
    // Use keytool.py to generate a new key
    unsigned char key4way [128] = "\x6c\x31\x10\x89\x36\x54\x06\x49\xb8\x3b\xc5\x4b\xe2\x5e\xd3\x8b\x7a\xc9\x40\x76\xa9\x83\xac\x10\x70\xf3\x77\xe8\xa3\xb9\x9b\x8e\x81\x4f\xe5\xf5\x80\x8d\x1c\xa7\x0e\xbd\xf7\x0d\x0f\x7f\x0e\x5f\xaa\x0b\xee\xc6\x93\xf7\x79\xfc\x52\x5f\x6d\xb8\x6b\xa3\xfa\x82\x5b\xf0\xef\x65\xfd\x70\xb2\x31\x87\x6b\x54\x85\x21\xeb\x09\xd1\x17\x5c\xfd\x1c\x35\x6d\x44\x60\x71\xd1\xcc\xbf\x53\xe0\x75\xc3\x8b\x1f\xd4\xbf\x4b\x99\x45\xc7\x01\x3a\x2f\x06\xc1\xbc\xbe\x7e\xc4\xf3\xcc\x93\x42\x6a\xdf\x21\x3a\xb2\xf8\x92\xbc\x2b\xeb\x20";

    // iv, iv_salt, data all initialized to 0
    unsigned char iv[32] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    unsigned char iv_salt[32] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    unsigned char data[32] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    while (true) {
        char cmd = getchar();
        // Command "K": Set key. Expects 4-way AES key.
        if(cmd == 'K') {
            readuart(key4way, 128);
            printf("OK");
        // Command "E": Perform encryption.
        } else if (cmd == 'E') {
            // Restore scratch-buffer
            memcpy(scratch_ptr, scratch_backup, 2048);
            memcpy(iv, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32);
            memcpy(iv_salt, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32);
            memcpy(data, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32);
            gpio_put(TRIGGER, 1);
            sleep_ms(1);
            gpio_put(TRIGGER, 0);
            decrypt(key4way, iv_salt, iv, &data, 1);
            for(int i=0; i < 16; i++) {
                printf("%02X", data[i]);
            }
        }
    }
}
