/* Copyright 2019-2021 Lenovo */

#include "sha-256.h"
#include <arpa/inet.h>
#include <crypt.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define MAXPACKET 1024

static const char cryptalpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
static const char b64alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char* genpasswd(int len) {
        unsigned char * passwd;
        int urandom, ret;
        passwd = calloc(len + 1, sizeof(char));
        urandom = open("/dev/urandom", O_RDONLY);
        if (urandom < 0) {
            fprintf(stderr, "Failed reading /dev/urandom\n");
            exit(1);
        }
        ret = read(urandom, passwd, len);
        close(urandom);
        for (urandom = 0; urandom < len; urandom++) {
                passwd[urandom] = cryptalpha[passwd[urandom] >> 2];
        }
        passwd[len] = 0;  // Should be redundant with calloc, but be explicit
        return passwd;

}

char * b64e(uint8_t * data, uint32_t datalen) {
    uint8_t * currptr;
    uint8_t * currout;
    uint8_t currchunk[4];
    uint8_t * retval;
    uint32_t neededlen;
    int32_t remaining = datalen;
    neededlen = (datalen - 1) / 3 * 4 + 4;
    retval = malloc(neededlen + 1);
    currout = retval;
    currptr = data;
    currchunk[3] = 0;
    while (remaining > 0) {
        currchunk[0] = currptr[0];
        currchunk[1] = remaining > 1 ? currptr[1] : 0;
        currchunk[2] = remaining > 2 ? currptr[2] : 0;
        currptr += 3;
        currout[0] = b64alpha[currchunk[0] >> 2];
        currout[1] = b64alpha[(currchunk[0] << 4 | currchunk[1] >> 4) & 0x3f];
        currout[2] = remaining > 1 ? b64alpha[(currchunk[1] << 2 | currchunk[2] >> 6) & 0x3f] : '=';
        currout[3] = remaining > 2 ? b64alpha[currchunk[2] & 0x3f] : '=';
        remaining -= 3;
        currout += 4;
    }
    retval[neededlen] = 0;
    return retval;
}

int getpasshmac(int argc, char* argv[]) {
    FILE *outfile;
    uint8_t *passwd;
    uint8_t *buffer;
    uint8_t *tmps;
    uint8_t *cryptpass;
    uint8_t hmac[32];
    uint8_t *hmac64;
    uint8_t hmackey[64];
    int hmackeysize;
    if (argc < 5) {
        fprintf(stderr, "Usage: %s passfile cryptfile hmacfile hmackey\n", argv[0]);
        exit(1);
    }
    outfile = fopen(argv[4], "r");
    hmackeysize = fread(hmackey, 1, 64, outfile);
    fclose(outfile);
    passwd = genpasswd(48);
    outfile = fopen(argv[1], "w");
    buffer = malloc(20);
    tmps = genpasswd(16);
    memcpy(buffer, "$5$", 3);
    memcpy(buffer + 3, tmps, 16);
    free(tmps);
    buffer[19] = 0;
    fwrite(passwd, 1, 48, outfile);
    fclose(outfile);
    cryptpass = crypt(passwd, buffer);
    outfile = fopen(argv[2], "w");
    fwrite(cryptpass, 1, strlen(cryptpass), outfile);
    fclose(outfile);
    hmac_sha256(hmac, cryptpass, strlen(cryptpass), hmackey, hmackeysize);
    hmac64 = b64e(hmac, 32);
    outfile = fopen(argv[3], "w");
    fwrite(hmac64, 1, strlen(hmac64), outfile);
    fclose(outfile);
    free(hmac64);
    free(passwd);
    free(buffer);
    return 0;
}

int main(int argc, char* argv[]) {
        int sock, ret;
        char slen;
        unsigned char currtype;
        size_t currlen;
        unsigned char* passwd;
        unsigned char* cryptedpass;
        unsigned char* macaddr;
        struct timeval timeout;
        struct addrinfo hints;
        struct addrinfo *addrs;
        struct addrinfo *curr;
        struct sockaddr_in net4bind;
        struct sockaddr_in6 net6bind;
        FILE *hmackeyfile;
        uint8_t hmackey[64];
        uint8_t hmac[32];
        int hmackeysize = 0;
        unsigned char buffer[MAXPACKET];
        memset(&hints, 0, sizeof(struct addrinfo));
        memset(&net4bind, 0, sizeof(struct sockaddr_in));
        memset(&net6bind, 0, sizeof(struct sockaddr_in6));
        memset(&buffer, 0, MAXPACKET);
        memset(&timeout, 0, sizeof(struct timeval));
        if (strstr(argv[0], "genpasshmac") != NULL) {
            return getpasshmac(argc, argv);
        }
        timeout.tv_sec = 10;
        net4bind.sin_port = htons(302);
        net4bind.sin_family = AF_INET;
        net6bind.sin6_port = htons(302);
        net6bind.sin6_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        passwd = genpasswd(32);
        memset(buffer, 0, MAXPACKET);
        strncpy(buffer, "$5$", 3);
        cryptedpass = genpasswd(8);
        strncpy(buffer + 3, cryptedpass, 8);
        free(cryptedpass);
        cryptedpass = crypt(passwd, buffer);
        if (argc < 3) {
            fprintf(stderr, "Missing node name and manager\n");
            exit(1);
        }
        if (argc == 4) {
            hmackeyfile = fopen(argv[3], "r");
            hmackeysize = fread(hmackey, 1, 64, hmackeyfile);
            fclose(hmackeyfile);
            hmac_sha256(hmac, cryptedpass, strlen(cryptedpass), hmackey, hmackeysize);
        }
        sock = getaddrinfo(argv[2], "13001", &hints, &addrs);
        if (sock != 0) {
                fprintf(stderr, "Error trying to resolve %s\n", argv[2]);
                exit(1);
        }
        for (curr = addrs; curr != NULL; curr = curr->ai_next) {
                sock = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol);
                if (sock < 0) continue;
                if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
                    fprintf(stderr, "Failed setting reusaddr\n");
                }
                if (curr->ai_family == AF_INET) {
                    if (bind(sock, (struct sockaddr*)&net4bind, sizeof(struct sockaddr_in)) < 0) {
                        fprintf(stderr, "Unable to bind port 302\n");
                        exit(1);
                    }
                } else if (curr->ai_family == AF_INET6) {
                    if (bind(sock, (struct sockaddr*)&net6bind, sizeof(struct sockaddr_in6)) < 0) {
                        fprintf(stderr, "Unable to bind port 302\n");
                        exit(1);
                    }
                } else {
                        continue;
                }
                if (connect(sock, curr->ai_addr, curr->ai_addrlen) == 0) break;
        }
        if (curr == NULL) {
                fprintf(stderr, "Unable to reach %s\n", argv[2]);
                exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            fprintf(stderr, "Unable to set timeout\n");
        }
        freeaddrinfo(addrs);
        ret = read(sock, buffer, 8);
        if (memcmp(buffer, "\xc2\xd1-\xa8\x80\xd8j\xba", 8) != 0) {
                fprintf(stderr, "Unrecognized server\n");
                exit(1);
        }
        slen = strlen(argv[1]) & 0xff;
        dprintf(sock, "\x01%c%s", slen, argv[1]);
        if (hmackeysize) {
            ret = write(sock, "\x06\x20", 2);
            ret = write(sock, hmac, 32);
        } else
            ret = write(sock, "\x00\x00", 2);
        memset(buffer, 0, MAXPACKET);
        ret = read(sock, buffer, 2);
        while (buffer[0] != 255) {
            currtype = buffer[0];
	    if (currtype & 0b10000000) {
                currlen = buffer[1] << 8;
                while (read(sock, buffer, 1) < 0) {}; 
                currlen |= buffer[0];
            } else {
                currlen = buffer[1];
	    }
            memset(buffer, 0, MAXPACKET);
	    if (currlen > 1000) {
                fprintf(stderr, "Received oversized message\n");
                exit(1);
            }
            if (currlen) {
                ret = read(sock, buffer, currlen);  // Max is 1000, well under MAX_PACKET
                buffer[currlen] = 0;
            }
            if (currtype == 2) {
                dprintf(sock, "\x03%c", (int)currlen);
                ret = write(sock, buffer, currlen);
                slen = strlen(cryptedpass) & 0xff;
                dprintf(sock, "\x04%c%s", slen, cryptedpass);
                ret = write(sock, "\x00\x00", 2);
            } else if (currtype == 128) {
                printf("SEALED:%s", buffer);
                printf("\n");
                exit(0);
            } else if (currtype == 5) {
                printf("%s", passwd);
                printf("\n");
                exit(0);
            }
            buffer[0] = 255;
            ret = read(sock, buffer, 2);
        }
        fprintf(stderr, "Confluent API token grant denied by server\n");
        exit(1);
}
