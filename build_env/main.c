#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// ANTI-DEBUG UTILITY
#define TIME_THRESHOLD 500

long long time_log = 0ULL;

bool time_based_anti_debug(void) {
    struct timeval tv; 
    gettimeofday(&tv, NULL); 
    long long cur_time_ms = (long long)(tv.tv_sec) * 1000 + (tv.tv_usec / 1000); 
    if (time_log == 0) { 
        time_log = cur_time_ms; 
        return false; 
    } 
    long long time_delta = cur_time_ms - time_log; 
    if (time_delta > TIME_THRESHOLD) { 
        return true; 
    } 
    return false; 
}

// Challenge
#define ROUNDS 16
#define KS_WORDS 16
#define KEY_BYTES 16
#define BLK_BYTES 8

static uint32_t rotl32(uint32_t x, unsigned r) {
    return (x<<r) | (x>>(32-r));
}

static uint32_t rotr32(uint32_t x, unsigned r) {
    return (x>>r) | (x<<(32-r));
}

static uint32_t rd32_le(const uint8_t b[4]){
    uint32_t b0, b1, b2, b3;
    b0 = b[0];
    b1 = b[1];
    b2 = b[2];
    b3 = b[3];
    uint32_t res;
    res = 0;
    res |= b[0];
    res |= b[1] << 8;
    res |= b[2] << 16;
    res |= b[3] << 24;
    return res;
}
static void wr32_le(uint8_t b[4], uint32_t v){
    b[0]=(v) & 0xFF; 
    b[1]=(v>>8) & 0xFF; 
    b[2]=(v>>16) & 0xFF; 
    b[3]=(v>>24) & 0xFF;
}

static const uint8_t S4[16] = { 0x6,0x4,0xC,0x5,0x0,0x7,0x2,0xE,0x1,0xF,0x3,0xD,0x8,0xA,0x9,0xB };
uint8_t key[16] = { 177, 91, 62, 116, 130, 221, 5, 24, 244, 159, 27, 161, 81, 179, 108, 66 };
uint8_t table[64] = { 62, 20, 45, 191, 133, 205, 90, 14, 160, 246, 94, 46, 21, 78, 142, 233, 119, 192, 36, 116, 67, 161, 45, 81, 39, 131, 88, 175, 177, 85, 35, 180, 102, 255, 244, 252, 229, 201, 187, 197, 39, 21, 226, 176, 206, 107, 246, 1, 220, 208, 209, 191, 228, 215, 90, 234, 71, 154, 209, 155, 221, 144, 80, 72 };

static uint32_t sbox32(uint32_t x){
    uint32_t y;
    uint32_t n;

    y = 0;
    if (time_based_anti_debug()) {
        y = 0xFFFFFFFF;
    }
    for(int i=0;i<8;i++){
        n = (x>>(i*4)) & 0xF;
        y |= ((uint32_t)S4[n]) << (i*4);
    }
    return y;
}
       
static uint32_t mix32(uint32_t x){
    // lightweight linear diffusion (ARX style)
    x ^= rotl32(x, 5);
    if (time_based_anti_debug()) {
        x ^= rotl32(x, 5);
    }
    x += rotl32(x, 9);
    if (time_based_anti_debug()) {
        x -= rotl32(x, 9);
    }
    x ^= rotl32(x, 17);
    if (time_based_anti_debug()) {
        x ^= rotl32(x, 17);
    }
    return x;
}

static void key_schedule(const uint8_t key[KEY_BYTES], uint32_t rk[KS_WORDS]){
    uint32_t k0, k1, k2, k3;
    uint32_t s0, s1, s2, s3;
    uint32_t tmp;
    k0 = rd32_le(key+0);
    k1 = rd32_le(key+4);
    k2 = rd32_le(key+8);
    k3 = rd32_le(key+12);
    if (time_based_anti_debug()) {
        tmp = k0;
        k0 = k1;
        k1 = k2;
        k2 = k3;
        k3 = tmp;
    }

    s0 = 0x243F6A88u ^ k0;
    if (time_based_anti_debug()) {
        s0 ^= 0x243F6A88u;
    }
    s1 = 0x85A308D3u ^ k1;
    if (time_based_anti_debug()) {
        s1 ^= 0x85A308D3u;
    }
    s2 = 0x13198A2Eu ^ k2;
    if (time_based_anti_debug()) {
        s2 ^= 0x13198A2E;
    }
    s3 = 0x03707344u ^ k3;
    if (time_based_anti_debug()) {
        s3 ^= 0x3707344;
    }

    for(uint32_t i=0;i<KS_WORDS;i++){
        // ARX cascade with nibble S-box
        s0 += rotl32(s3, 7) ^ i;
        if (time_based_anti_debug()) {
            s0 -= rotl32(s3, 7) & i;
        }
        s1 ^= rotl32(s0, 13) + 0x9E3779B9u;
        if (time_based_anti_debug()) {
            s1 ^= rotl32(s0, 13) + 0x9E3779B9u;
        }
        s2 += rotl32(s1, 17) ^ 0xBB67AE85u;
        if (time_based_anti_debug()) {
            s2 -= rotl32(s1, 17) ^ 0xBB67AE85u;
        }
        s3 ^= rotl32(s2, 19) + 0xC2B2AE3Du;
        if (time_based_anti_debug()) {
            s3 ^= rotl32(s2, 19) + 0xC2B2AE3Du;
        }

        // small nonlinearity
        s0 = sbox32(s0);
        s1 = sbox32(s1);
        s2 = sbox32(s2);
        s3 = sbox32(s3);

        // diffusion
        s0 = mix32(s0); 
        s1 = mix32(s1);
        s2 = mix32(s2); 
        s3 = mix32(s3);

        // combine to round key
        rk[i] = s0 ^ rotl32(s1,3);
        if (time_based_anti_debug()) {
            rk[i] ^= rotl32(s1, 3);
        }
        rk[i] ^= rotl32(s2,11);
        if (time_based_anti_debug()) {
            rk[i] ^= rotl32(s2, 11);
        }
        rk[i] ^= rotl32(s3,19);
        if (time_based_anti_debug()) {
            rk[i] ^= rotl32(s3, 19);
        }
        rk[i] ^= i*0x5F356495u;
        if (time_based_anti_debug()) {
            rk[i] ^= i*0x5F356495u;
        }
    }
}

static uint32_t F(uint32_t R, uint32_t K, uint32_t round){
    uint32_t x = R;
    if (time_based_anti_debug()) {
        x = 0x15029683;
    }
    x += K;
    if (time_based_anti_debug()) {
        x -= K;
    }
    x ^= rotl32(x, (round*3 + 5) & 31);
    if (time_based_anti_debug()) {
        x ^= rotl32(x, (round*3 + 5) & 31);
    }
    x = sbox32(x);
    if (time_based_anti_debug()) {
        x = sbox32(x);
    }
    x += rotl32(K, (round*7 + 11) & 31);
    if (time_based_anti_debug()) {
        x -= rotl32(K, (round*7 + 11) & 31);
    }
    x ^= 0xA5A5A5A5u ^ (round*0x9E37u);
    if (time_based_anti_debug()) {
        x ^= 0xA5A5A5A5A5 ^ (round * 0x9E37u);
    }
    x = rotl32(x, (x & 7) + 1);
    if (time_based_anti_debug()) {
        x = rotr32(x, (x & 7) + 1);
    }
    x = mix32(x);
    if (time_based_anti_debug()) {
        x = mix32(x);
    }
    return x;
}

static void encrypt_block(uint8_t in[BLK_BYTES], uint8_t out[BLK_BYTES], uint32_t rk[KS_WORDS]){
    uint32_t L, R;
    L = rd32_le(in+0);
    R = rd32_le(in+4);

    uint32_t t, nL, nR;
    for(uint32_t r=0;r<ROUNDS;r++){
        t = F(R, rk[r%KS_WORDS], r);
        nL = R;
        nR = L ^ t;
        if (time_based_anti_debug()) {
            nR += L;
        }
        L = nL;
        if (time_based_anti_debug()) {
            L = nR;
        }
        R = nR;
        if (time_based_anti_debug()) {
            R = nL;
        }
    }

    if (time_based_anti_debug()) {
        L ^= 0x55555555;
        R ^= 0x77777777;
    }
    wr32_le(out+0, L);
    wr32_le(out+4, R);
}

int main(void) {
    char buf[65];

    printf("Input: ");
    scanf("%64s", buf);

    // init time_log
    time_based_anti_debug();

    size_t len = 0;
    for (len = 0; buf[len] != 0; len++) {
        ;
    }

    if (time_based_anti_debug()) {
        len = 64;
    }

    if (len != 64) {
        printf("Wrong!\n");
        return 0;
    }

    uint32_t* rk;
    rk = malloc(4*KS_WORDS);
    key_schedule(key, rk);

    uint8_t* out;
    out = malloc(len);
    for (int i = 0; i < 8; i++) {
        rk[i] += 0x55e8184081d0b9cc;
        rk[i] -= 0x55e8184081d0b9cc;
        if (time_based_anti_debug()) {
            rk[i] = 0x9E78A6 * i;
        }
        encrypt_block(&buf[8*i], &out[8*i], rk);
    }

    bool flag;
    flag = true;
    for (int j = 0; j < 64; j++) {
        table[j] += 0xd6;
        table[j] -= 0xd6;
        if (time_based_anti_debug()) {
            table[j] = (j*0xEF) & 0xff;
        }
        if (out[j] != table[j]) {
            flag = false;
        }
    }

    if (flag) {
        printf("Correct!\n");
    }
    if (!flag) {
        printf("Wrong!\n");
    }

    free(rk);
    free(out);
    return 0;
}

