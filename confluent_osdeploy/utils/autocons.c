#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define COM1 0x3f8
#define COM2 0x2f8
#define COM3 0x3e8
#define COM4 0x2e8

#define SPEEDNOOP 0
#define SPEED9600 3
#define SPEED19200 4
#define SPEED57600 6
#define SPEED115200 7

typedef struct {
    char devnode[32];
    speed_t speed;
    int valid;
} serial_port_t;

serial_port_t process_spcr() {
    serial_port_t result = {0};
    char buff[128];
    int fd;
    uint64_t address;
    int currspeed;
    
    result.valid = 0;
    
    fd = open("/sys/firmware/acpi/tables/SPCR", O_RDONLY);
    if (fd < 0) {
        return result;
    }
    
    if (read(fd, buff, 80) < 80) {
        close(fd);
        return result;
    }
    close(fd);
    
    if (buff[8] != 2) return result; // revision 2
    if (buff[36] != 0) return result; // 16550 only
    if (buff[40] != 1) return result; // IO only
    
    address = *(uint64_t *)(buff + 44);
    currspeed = buff[58];
    
    if (address == COM1) {
        strncpy(result.devnode, "/dev/ttyS0", sizeof(result.devnode));
    } else if (address == COM2) {
        strncpy(result.devnode, "/dev/ttyS1", sizeof(result.devnode));
    } else if (address == COM3) {
        strncpy(result.devnode, "/dev/ttyS2", sizeof(result.devnode));
    } else if (address == COM4) {
        strncpy(result.devnode, "/dev/ttyS3", sizeof(result.devnode));
    } else {
        return result;
    }
    
    if (currspeed == SPEED9600) {
        result.speed = B9600;
    } else if (currspeed == SPEED19200) {
        result.speed = B19200;
    } else if (currspeed == SPEED57600) {
        result.speed = B57600;
    } else if (currspeed == SPEED115200) {
        result.speed = B115200;
    } else {
        return result;
    }
    
    result.valid = 1;
    return result;
}

serial_port_t identify_by_sys_vendor() {
    serial_port_t result = {0};
    char buff[128];
    FILE *f;
    
    f = fopen("/sys/devices/virtual/dmi/id/sys_vendor", "r");
    if (f) {
        if (fgets(buff, sizeof(buff), f)) {
            if (strstr(buff, "Supermicro")) {
                strncpy(result.devnode, "/dev/ttyS1", sizeof(result.devnode));
                result.speed = B115200;
                result.valid = 1;
            }
        }
        fclose(f);
    }
    return result;
}

serial_port_t search_serial_ports() {
    serial_port_t result = {0};
    DIR *dir;
    struct dirent *entry;
    int fd;
    int status;
    int numfound= 0;

    dir = opendir("/dev");
    if (!dir) {
        return result;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "ttyS", 4) != 0) {
            continue;
        }
        
        char devpath[64];
        snprintf(devpath, sizeof(devpath), "/dev/%s", entry->d_name);
        
        fd = open(devpath, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) {
            continue;
        }
        
        if (ioctl(fd, TIOCMGET, &status) == 0) {
            if (status & TIOCM_CAR) {
                strncpy(result.devnode, devpath, sizeof(result.devnode));
                numfound++;
                result.speed = B115200;
                
            }
        }
        
        close(fd);
    }
    
    closedir(dir);
    if (numfound == 1) {
        result.valid = 1;
    }
    return result;
}

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
    #ifndef __x86_64__
        // Only x86 needs autoconsole, other platforms have reasonable default serial console
        exit(0);
    #endif
    serial_port_t spcr = process_spcr();
    if (!spcr.valid) {
        spcr = search_serial_ports();
    }
    if (!spcr.valid) {
        spcr = identify_by_sys_vendor();
    }
    if (!spcr.valid) {
        exit(0);
    }
    strncpy(buff, spcr.devnode, sizeof(buff));
    offset = strchr(buff, 0);
    currspeed = spcr.speed;
    ttyf = open(buff, O_RDWR | O_NOCTTY);
    if (ttyf < 0) {
        fprintf(stderr, "Unable to open tty\n");
        exit(1);
    }
    if (currspeed == B9600) {
        cspeed = B9600;
        strncpy(offset, ",9600", 6);
    } else if (currspeed == B19200) {
        cspeed = B19200;
        strncpy(offset, ",19200", 7);
    } else if (currspeed == B57600) {
        cspeed = B57600;
        strncpy(offset, ",57600", 7);
    } else if (currspeed == B115200) {
        cspeed = B115200;
        strncpy(offset, ",115200", 8);
    } else {
        exit(0);
    }
    tcgetattr(ttyf, &tty);
    if (cspeed) {
        cfsetospeed(&tty, cspeed);
        cfsetispeed(&tty, cspeed);
    }
    buff[127] = 0;
    printf("%s\n", buff);
    tcgetattr(ttyf, &tty2);
    cfmakeraw(&tty2);
    tcsetattr(ttyf, TCSANOW, &tty2);
    flags = fcntl(ttyf, F_GETFL, 0);
    if (fcntl(ttyf, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "Failed setting flags on tty\n");
    }
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
    if (argc > 1 && (strcmp(argv[1], "-c") == 0)) {
        ioctl(ttyf, TIOCCONS, 0);
    }
}

