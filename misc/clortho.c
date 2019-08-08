/* Copyright 2019 Lenovo */
#include <arpa/inet.h>
#include <crypt.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define OUI_ETHERTYPE 0x88b7
#define MAXPACKET 1024
#define CHDR "\xa4\x8c\xdb\x30\x01"

int get_interface_index(int sock, char *interface) {
        struct ifreq req;
        memset(&req, 0, sizeof(req));
        strncpy(req.ifr_name, interface, IFNAMSIZ);
        if (ioctl(sock, SIOCGIFINDEX, &req) < 0) {
                return -1;
        }
        return req.ifr_ifindex;
}

unsigned char* genpasswd() {
        unsigned char * passwd;
        int urandom;
        passwd = calloc(33, sizeof(char));
        urandom = open("/dev/urandom", O_RDONLY);
        read(urandom, passwd, 32);
        close(urandom);
        for (urandom = 0; urandom < 32; urandom++) {
                passwd[urandom] = 0x30 + (passwd[urandom] >> 2);
        }
        return passwd;

}

int parse_macaddr(char* macaddr) {
        unsigned char *curr;
        unsigned char idx;
        curr = strtok(macaddr, ":-");
        idx = 0;

        while (curr != NULL) {
                macaddr[idx++] = strtoul(curr, NULL, 16);
                curr = strtok(NULL, ":-");
        }

}

int main(int argc, char* argv[]) {
        int sock;
        int iface;
        unsigned char* passwd;
        unsigned char* macaddr;

        unsigned char buffer[MAXPACKET];

        passwd = genpasswd();
        if (argc < 3) { 
            fprintf(stderr, "Missing interface name and target MAC\n");
            exit(1);
        }
        printf("%s\n", argv[2]);
        parse_macaddr(argv[2]);
        printf("%s\n", argv[2]);
        sock = socket(AF_PACKET, SOCK_DGRAM, htons(OUI_ETHERTYPE));
        if (sock < 0) {
                fprintf(stderr, "Unable to open socket (run as root?)\n");
                exit(1);
        }
        iface = get_interface_index(sock, argv[1]);
        if (iface < 0) {
                fprintf(stderr, "Unable to find specified interface '%s'\n", argv[1]);
                exit(1);
        }


}

