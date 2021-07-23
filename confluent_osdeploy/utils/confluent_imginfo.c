#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int read_part(FILE* img, long int imgsize) {
    char mountpath[65537];
    char devpath[65537];
    char fstype[65537];
    uint16_t shortlength;
    uint32_t length;
    uint64_t longlength;
    fread(&shortlength, 2, 1, img);
    shortlength = be16toh(shortlength);
    fread(mountpath, 1, shortlength, img);
    mountpath[shortlength] = 0;
    fread(&length, 4, 1, img);
    length = be32toh(length);
    fseek(img, length, SEEK_CUR); // skip json section that we don't support
    fread(&longlength, 8, 1, img); // minimum size in bytes
    longlength = be64toh(longlength);
    printf("%ld\t", longlength);
    fread(&longlength, 8, 1, img); // default size in bytes
    longlength = be64toh(longlength);
    printf("%ld\t", longlength);
    fread(&shortlength, 2, 1, img); // length of filesystem type
    shortlength = be16toh(shortlength);
    fread(fstype, 1, shortlength, img);
    fstype[shortlength] = 0;
    fread(&shortlength, 2, 1, img); // length of DEVICE
    shortlength = be16toh(shortlength);
    fread(devpath, 1, shortlength, img);
    devpath[shortlength] = 0;
    fread(&shortlength, 2, 1, img);
    shortlength = be16toh(shortlength);
    fseek(img, shortlength, SEEK_CUR); // Skip the padding
    fread(&longlength, 8, 1, img);
    longlength = be64toh(longlength);
    printf("%ld\t", ftell(img) / 512);
    printf("%ld\t", longlength / 512);
    printf("%s\t%s\t%s\n", fstype, devpath, mountpath);
    fseek(img, longlength, SEEK_CUR);
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
        fread(buffer, 1, 1, img);
        fseek(img, buffer[0], SEEK_CUR);
        while (read_part(img, imgsize));
        exit(0);
    }
    if (memcmp(buffer, "\xaa\xd5\x0f\x7e\x5d\xfb\x4b\x7c\xa1\x2a\xf4\x0b\x6d\x94\xf7\xfc", 16) == 0) {
        fread(buffer, 1, 1, img);
        fseek(img, buffer[0], SEEK_CUR);
        fread(buffer, 1, 1, img);
        if (buffer[0] == 0) {
            printf("Format: confluent_crypted\n");
            exit(0);
        }
    }
    fprintf(stderr, "Unrecognized image format\n");
    exit(1);

}
