#include "boar.h"

boar_dev *new_boar_dev(boar_dev_cfg *dev_cfg) {
    boar_dev *dev = malloc(sizeof(*dev));

    // char *if2_name = "TAP200";
    char *if2_name = dev_cfg->interface;
    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        die();
    struct ifreq ifr;
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, if2_name, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
        die();

    char cmd[128];
    // sprintf(cmd, "sudo ifconfig %s %u.%u.%u.%u", if2_name,
    //     dev_cfg->address[0],
    //     dev_cfg->address[1],
    //     dev_cfg->address[2],
    //     dev_cfg->address[3]);
    // sprintf(cmd, "sudo ifconfig %s %s", if2_name, dev_cfg->address);
    sprintf(cmd, "sudo ip addr add %s/24 dev %s && ip link set %s up",
        dev_cfg->address, if2_name, if2_name);
    // if (system("sudo ifconfig TAP200 192.168.5.1") < 0)
    //     die();
    if (system(cmd) < 0)
        die();

    dev->fd = fd;

    return dev;
}

uint32_t boar_dev_read(boar_dev *dev, uint8_t *buf, uint32_t len) {
    return read(dev->fd, buf, len);
}

uint32_t boar_dev_write(boar_dev *dev, uint8_t *buf, uint32_t len) {
    return write(dev->fd, buf, len);
}
