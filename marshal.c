#include "marshal.h"

void marshal8(uint8_t value, uint8_t *ptr) {
    ptr[0] = value;
}

void marshal16(uint16_t value, uint8_t *ptr) {
    ptr[0] = value >> 8;
    ptr[1] = value & 0xff;
}

void marshal32(uint32_t value, uint8_t *ptr) {
    ptr[0] = value >> 24;
    ptr[1] = (value & 0xffffff) >> 16;
    ptr[2] = (value & 0xffff) >> 8;
    ptr[3] = value & 0xff;
}

void marshal64(uint64_t value, uint8_t *ptr) {
    ptr[0] = value >> 56;
    ptr[1] = (value & 0x00ffffffffffffff) >> 48;
    ptr[2] = (value & 0x0000ffffffffffff) >> 40;
    ptr[3] = (value & 0x000000ffffffffff) >> 32;
    ptr[4] = (value & 0x00000000ffffffff) >> 24;
    ptr[5] = (value & 0x0000000000ffffff) >> 16;
    ptr[6] = (value & 0x000000000000ffff) >> 8;
    ptr[7] = value & 0xff;
}

uint8_t unmarshal8(uint8_t *ptr) {
    return *ptr;
}

uint16_t unmarshal16(uint8_t *ptr) {
    return ((uint16_t)*ptr << 8) + (uint16_t)*(ptr + 1);
}

uint32_t unmarshal32(uint8_t *ptr) {
    return ((uint32_t)*ptr << 24) + ((uint32_t)*(ptr + 1) << 16) +
           ((uint32_t)*(ptr + 2) << 8) + (uint32_t)*(ptr + 3);
}

uint64_t unmarshal64(uint8_t *ptr) {
    return ((uint64_t)*ptr << 56) + ((uint64_t)*(ptr + 1) << 48) +
           ((uint64_t)*(ptr + 2) << 40) + ((uint64_t)*(ptr + 3) << 32) +
           ((uint64_t)*(ptr + 4) << 24) + ((uint64_t)*(ptr + 5) << 16) +
           ((uint64_t)*(ptr + 6) << 8) + (uint64_t)*(ptr + 7);
}

// (un)marshal*_mp functions: (un)marshal and move ptr

uint8_t *marshal8_mp(uint8_t value, uint8_t  *ptr) {
    marshal8(value, ptr);
    ptr += 1;
    return ptr;
}

uint8_t *marshal16_mp(uint16_t value, uint8_t *ptr) {
    marshal16(value, ptr);
    ptr += 2;
    return ptr;
}

uint8_t *marshal32_mp(uint32_t value, uint8_t *ptr) {
    marshal32(value, ptr);
    ptr += 4;
    return ptr;
}

uint8_t *marshal64_mp(uint64_t value, uint8_t *ptr) {
    marshal64(value, ptr);
    ptr += 8;
    return ptr;
}

uint8_t unmarshal8_mp(uint8_t **ptr) {
    uint8_t ret = unmarshal8(*ptr);
    *ptr += 1;
    return ret;
}

uint16_t unmarshal16_mp(uint8_t **ptr) {
    uint16_t ret = unmarshal16(*ptr);
    *ptr += 2;
    return ret;
}

uint32_t unmarshal32_mp(uint8_t **ptr) {
    uint32_t ret = unmarshal32(*ptr);
    *ptr += 4;
    return ret;
}

uint64_t unmarshal64_mp(uint8_t **ptr) {
    uint64_t ret = unmarshal64(*ptr);
    *ptr += 8;
    return ret;
}
