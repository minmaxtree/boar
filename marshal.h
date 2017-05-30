#ifndef __MARSHAL_H__
#define __MARSHAL_H__

#include "boar.h"

void marshal8(uint8_t value, uint8_t *ptr);
void marshal16(uint16_t value, uint8_t *ptr);
void marshal32(uint32_t value, uint8_t *ptr);
void marshal64(uint64_t value, uint8_t *ptr);
uint8_t unmarshal8(uint8_t *ptr);
uint16_t unmarshal16(uint8_t *ptr);
uint32_t unmarshal32(uint8_t *ptr);
uint64_t unmarshal64(uint8_t *ptr);
// (un)marshal*_mp functions: (un)marshal and move ptr
uint8_t *marshal8_mp(uint8_t value, uint8_t  *ptr);
uint8_t *marshal16_mp(uint16_t value, uint8_t *ptr);
uint8_t *marshal32_mp(uint32_t value, uint8_t *ptr);
uint8_t *marshal64_mp(uint64_t value, uint8_t *ptr);
uint8_t unmarshal8_mp(uint8_t **ptr);
uint16_t unmarshal16_mp(uint8_t **ptr);
uint32_t unmarshal32_mp(uint8_t **ptr);
uint64_t unmarshal64_mp(uint8_t **ptr);

#endif
