#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int read_part(FILE* img, long int imgsize) {
    char * mountpath;
    char * devpath;
    char * fstype;
    uint16_t shortlength;
    uint32_t length;
    uint64_t longlength;
    if (fread(&shortlength, 2, 1, img) < 1) {
        fprintf(stderr, "Error reading section\n");
        exit(1);
    }
    shortlength = be16toh(shortlength);
    mountpath = (char*)malloc(shortlength + 1);
    if (fread(mountpath, 1, shortlength, img) < shortlength) {
        fprintf(stderr, "Failure reading segment\n");
        exit(1);
    }
    mountpath[shortlength] = 0;
    if (fread(&length, 4, 1, img) < 1) {
        fprintf(stderr, "Failure reading segment\n");
        exit(1);
    }
    length = be32toh(length);
    if (fseek(img, length, SEEK_CUR) != 0) { // skip json section that we don't support
        fprintf(stderr, "Error skipping json segment");
        exit(1);
    }
    if (fread(&longlength, 8, 1, img) < 1) { // minimum size in bytes
        fprintf(stderr, "Failure reading segment\n");
        exit(1);
    }
    longlength = be64toh(longlength);
    printf("%ld\t", longlength);
    if (fread(&longlength, 8, 1, img) < 1) { // default size in bytes
        fprintf(stderr, "Error reading segment\n");
        exit(1);
    }
    longlength = be64toh(longlength);
    printf("%ld\t", longlength);
    if (fread(&shortlength, 2, 1, img) < 1) { // length of filesystem type
        fprintf(stderr, "Error reading segment\n");
        exit(1);
    }
    shortlength = be16toh(shortlength);
    fstype = (char*)malloc(shortlength + 1);
    if (fread(fstype, 1, shortlength, img) < shortlength) {
        fprintf(stderr, "Error reading segment\n");
        exit(1);
    }
    fstype[shortlength] = 0;
    if (fread(&shortlength, 2, 1, img) < 1) { // length of DEVICE
        fprintf(stderr, "Error reading segment\n");
        exit(1);
    }
    shortlength = be16toh(shortlength);
    devpath = (char*)malloc(shortlength + 1);
    if (fread(devpath, 1, shortlength, img) < shortlength) {
        fprintf(stderr, "Error reading segment\n");
        exit(1);
    }
    devpath[shortlength] = 0;
    if (fread(&shortlength, 2, 1, img) < 1) {
        fprintf(stderr, "Error reading segment\n");
        exit(1);
    }
    shortlength = be16toh(shortlength);
    if (fseek(img, shortlength, SEEK_CUR) != 0) { // Skip the padding
        fprintf(stderr, "Failure skipping padding\n");
        exit(1);
    }
    if (fread(&longlength, 8, 1, img) < 1) {
        fprintf(stderr, "Error reading section\n");
        exit(1);
    }
    longlength = be64toh(longlength);
    printf("%ld\t", ftell(img) / 512);
    printf("%ld\t", longlength / 512);
    printf("%s\t%s\t%s\n", fstype, devpath, mountpath);
    free(mountpath);
    free(devpath);
    free(fstype);
    if (fseek(img, longlength, SEEK_CUR) != 0) {
        fprintf(stderr, "Error restoring seek\n");
        exit(1);
    }
    return (ftell(img) < imgsize);
}

int main(int argc, char* argv[]) {
    FILE* img;
    long int imgsize;
    char buffer[20];

    img = fopen(argv[1], "rb");
    fseek(img, 0, SEEK_END);
    imgsize = ftell(img);
    fseek(img, 0, SEEK_SET);
    if (fread(buffer, 1, 16, img) < 16) {
        fprintf(stderr, "Unable to read header of image\n");
        exit(1);
    }
    if ((memcmp(buffer, "hsqs", 4) == 0) || (memcmp(buffer, "sqsh", 4) == 0)) {
        printf("Format: squashfs\n");
        exit(0);
    }
    if (memcmp(buffer, "\x63\x7b\x9d\x26\xb7\xfd\x48\x30\x89\xf9\x11\xcf\x18\xfd\xff\xa1", 16) == 0) {
        printf("Format: confluent_multisquash\nminsize\tdefsize\toffset\tsize\tfstype\torigdev\tmount\n");
        if (fread(buffer, 1, 1, img) < 1) {
            fprintf(stderr, "Error reading image\n");
            exit(1);
        }
        if (fseek(img, buffer[0], SEEK_CUR) != 0) {
            fprintf(stderr, "Error seeking in image\n");
            exit(1);
        }
        while (read_part(img, imgsize));
        exit(0);
    }
    if (memcmp(buffer, "\xaa\xd5\x0f\x7e\x5d\xfb\x4b\x7c\xa1\x2a\xf4\x0b\x6d\x94\xf7\xfc", 16) == 0) {
        if (fread(buffer, 1, 1, img) < 1) {
            fprintf(stderr, "Error reading image\n");
            exit(1);
        }
        if (fseek(img, buffer[0], SEEK_CUR) != 0) {
            fprintf(stderr, "Error reading image\n");
            exit(1);
        }
        if (fread(buffer, 1, 1, img) < 1) {
            fprintf(stderr, "Error reading image\n");
            exit(1);
        }
        if (buffer[0] == 0) {
            printf("Format: confluent_crypted\n");
            exit(0);
        }
    }
    fprintf(stderr, "Unrecognized image format\n");
    exit(1);

}
