#include <termios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define COM1 0x3f8
#define COM2 0x2f8
#define COM3 0x3e8
#define COM4 0x2e8

#define SPEEDNOOP 0
#define SPEED9600 3
#define SPEED19200 4
#define SPEED57600 6
#define SPEED115200 7

int main(int argc, char* argv[]) {
    struct termios tty;
    int ttyf;
    int spcr;
    int currspeed;
    speed_t cspeed;
    char buff[128];
    char* offset;
    uint64_t address;
    spcr = open("/sys/firmware/acpi/tables/SPCR", O_RDONLY);
    if (spcr < 0) {
        exit(0);
    }
    if (read(spcr, buff, 80) < 80) {
        exit(0);
    }
    if (buff[8] != 2) exit(0); //revision 2
    if (buff[36] != 0) exit(0); //16550 only
    if (buff[40] != 1) exit(0); //IO only
    address = *(uint64_t *)(buff + 44);
    currspeed = buff[58];
    offset = buff + 10;
    if (address == COM1) {
        strncpy(buff, "/dev/ttyS0", 128);
    } else if (address == COM2) {
        strncpy(buff, "/dev/ttyS1", 128);
    } else if (address == COM3) {
        strncpy(buff, "/dev/ttyS2", 128);
    } else if (address == COM4) {
        strncpy(buff, "/dev/ttyS3", 128);
    } else {
        exit(0);
    }
    ttyf = open(buff, O_RDWR | O_NOCTTY);
    if (currspeed == SPEED9600) {
        cspeed = B9600;
        strcpy(offset, ",9600");
    } else if (currspeed == SPEED19200) {
        cspeed = B19200;
        strcpy(offset, ",19200");
    } else if (currspeed == SPEED57600) {
        cspeed = B57600;
        strcpy(offset, ",57600");
    } else if (currspeed == SPEED115200) {
        cspeed = B115200;
        strcpy(offset, ",115200");
    } else {
        exit(0);
    }
    tcgetattr(ttyf, &tty);
    if (cspeed) {
        cfsetospeed(&tty, B115200);
        cfsetispeed(&tty, B115200);
    }
    tcsetattr(ttyf, TCSANOW, &tty);
    ioctl(ttyf, TIOCCONS, 0);
    printf("%s\n", buff);

}

