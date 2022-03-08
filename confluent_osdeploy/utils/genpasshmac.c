#include "sha-256.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

static const char cryptalpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

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


int main(int argc, char* argv[]) {
    FILE *outfile;
    uint8_t *passwd;
    uint8_t *buffer;
    uint8_t *tmps;
    uint8_t *cryptpass;
    uint8_t hmac[32];
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
    buffer[19] = 0;
    fwrite(passwd, 1, 48, outfile);
    fclose(outfile);
    cryptpass = crypt(passwd, buffer);
    outfile = fopen(argv[2], "w");
    fwrite(cryptpass, 1, strlen(cryptpass), outfile);
    fclose(outfile);
    hmac_sha256(hmac, cryptpass, strlen(cryptpass), hmackey, hmackeysize);
    outfile = fopen(argv[3], "w");
    fwrite(hmac, 1, 32, outfile);
    fclose(outfile);
    free(passwd);
    free(buffer);
}

