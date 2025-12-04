#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t rotl32(uint32_t x, unsigned shift) {
    shift &= 31u;
    return (x << shift) | (x >> (32u - shift));
}

int main(void) {
    unsigned char buf[64];

    printf("Enter the 8-byte key: ");
    fflush(stdout);

    if (!fgets((char *)buf, sizeof(buf), stdin)) {
        return 1;
    }

    size_t len = strcspn((char *)buf, "\n");
    buf[len] = '\0';

    if (len != 8) {
        puts("nope");
        return 0;
    }

    uint32_t stateA = 0xA5C3F1B2u;
    uint32_t stateB = 0x1F2E3D4Cu;

    for (size_t i = 0; i < len; ++i) {
        uint32_t c = buf[i];
        uint32_t rotated = rotl32(c * 0x11u, (unsigned)((i % 5u) + 1u));
        stateA = (stateA + rotated) ^ (stateB + (c << (i & 3u)));

        uint32_t tweak = c * 0x45u + (uint32_t)i;
        stateB = rotl32(stateB ^ tweak, (unsigned)(((i + 3u) % 7u) + 1u));
        stateB += stateA;
    }

    uint32_t finalA = stateA ^ 0xCAFEBABEu;
    uint32_t finalB = (stateB + (len * 0x1234u)) ^ 0x0F0F0F0Fu;

    if (finalA == 0x9B1B6A81u && finalB == 0x1073B6DEu) {
        puts("Correct");
    } else {
        puts("Wrong");
    }

    return 0;
}
