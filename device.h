#ifndef __DEVICE_H__
#define __DEVICE_H__

#include "boar.h"

typedef struct boar_dev {
    int fd;
} boar_dev;

boar_dev *new_boar_dev();

uint32_t boar_dev_read(boar_dev *dev, uint8_t *buf, uint32_t len);

uint32_t boar_dev_write(boar_dev *dev, uint8_t *buf, uint32_t len);

typedef struct {
    char interface[128];
    // uint8_t address[4];
    char address[128];
} boar_dev_cfg;

#endif
