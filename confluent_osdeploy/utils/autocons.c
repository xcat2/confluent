#include <errno.h>
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
    struct termios tty2;
    struct winsize ws;
    unsigned width, height;
    int ttyf;
    int tmpi;
    int currspeed;
    int flags;
    speed_t cspeed;
    char buff[128];
    int bufflen;
    fd_set set;
    struct timeval timeout;
    char* offset;
    uint64_t address;
    bufflen = 0;
    tmpi = open("/sys/firmware/acpi/tables/SPCR", O_RDONLY);
    if (tmpi < 0) {
        exit(0);
    }
    if (read(tmpi, buff, 80) < 80) {
        exit(0);
    }
    close(tmpi);
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
        cfsetospeed(&tty, cspeed);
        cfsetispeed(&tty, cspeed);
    }
    printf("%s\n", buff);
    tcgetattr(ttyf, &tty2);
    cfmakeraw(&tty2);
    tcsetattr(ttyf, TCSANOW, &tty2);
    flags = fcntl(ttyf, F_GETFL, 0);
    fcntl(ttyf, F_SETFL, flags | O_NONBLOCK);
    while (read(ttyf, buff, 64) > 0) {
        // Drain any pending reads
    }
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;
    FD_ZERO(&set);
    FD_SET(ttyf, &set);
    if (write(ttyf, "\0337\033[999;999H\033[6n\0338", 18) < 0) {};
    while (select(ttyf + 1, &set, NULL, NULL, &timeout) > 0) {
        if ((tmpi = read(ttyf, buff + bufflen, 127 - bufflen)) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else {
                break;
            }
        }
        bufflen += tmpi;
        buff[bufflen] = 0;
        if (strchr(buff, 'R')) {
            break;
        }
    }
    fcntl(ttyf, F_SETFL, flags);
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    if (sscanf(buff, "\033[%u;%uR", &height, &width) == 2) {
        ws.ws_col = width;
        ws.ws_row = height;
    } else {
        ws.ws_col = 100;
        ws.ws_row = 31;
    }
    if (ws.ws_col < 80) { ws.ws_col = 80; }
    if (ws.ws_row < 24) { ws.ws_col = 24; }
    ioctl(ttyf, TIOCSWINSZ, &ws);
    tcsetattr(ttyf, TCSANOW, &tty);
    ioctl(ttyf, TIOCCONS, 0);
}

