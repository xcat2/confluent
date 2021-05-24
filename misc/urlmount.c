/*
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2021 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
*/

#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <curl/curl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

CURL *curl;

char curlerror[CURL_ERROR_SIZE];
curl_off_t filesize;

typedef struct downloadbuffer {
    char *response;
    size_t completed;
    size_t total;
} downloadbuffer;

#define MAX_FILE_LEN 1024
#define MAX_URL_PATHS 512
static char filename[MAX_FILE_LEN];
static int urlidx;
static char* urls[MAX_URL_PATHS];


static int http_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    if (strcmp(path, "/") != 0)  // We don't support subdirs
        return -ENOENT;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, filename + 1, NULL, 0);
    return 0;
}

size_t fill_buffer(char *data, size_t size, size_t nmemb, downloadbuffer *userdata) {
    size_t amount;
    amount = size * nmemb;
    if (userdata->total < amount + userdata->completed) return 0;
    memcpy(&(userdata->response[userdata->completed]), data, amount);
    userdata->completed += amount;
    return amount;
}

static int http_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    char headbuffer[512];
    double dldbl = 0.0;
    int startidx;
    int reconnecting = 0;
    FILE* fd;
    startidx = urlidx;
    memset(buf, 0, size);
    curl_off_t downloaded;
    //Would be needed for multithread, however preferring to conserve
    //filehandles rather than go multithread
    // Some comparisons showed that the threaded performance boost doesn't
    // do even offset the overhead of the new curl handles, so better
    // to use single threaded curl overall for now
    //CURL *tmpcurl = curl_easy_duphandle(curl);
    downloadbuffer dlbuf;
    dlbuf.response = buf;
    dlbuf.completed = 0;
    dlbuf.total = size;
    fd = NULL;

    if (strcmp(path, filename) != 0) return -ENOENT;
    memset(headbuffer, 0, 512);
    snprintf(headbuffer, 512, "%ld-%ld", offset, offset + size - 1);
    curl_easy_setopt(curl, CURLOPT_RANGE, headbuffer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &dlbuf);
    while (curl_easy_perform(curl) != CURLE_OK) {
        reconnecting = 1;
        fd = fopen("/dev/kmsg", "w+");
        dlbuf.completed = 0;
        fprintf(fd, "<1>urlmount: error while communicating with %s: %s\n", urls[urlidx], curlerror);
        urlidx++;
        if (urls[urlidx] == NULL)
            urlidx = 0;
        if (urlidx == startidx)
            sleep(10);
        fprintf(fd, "urlmount: Connecting to %s\n", urls[urlidx]);
        curl_easy_setopt(curl, CURLOPT_URL, urls[urlidx]);
        fclose(fd);
    }
    if (reconnecting) {
        fd = fopen("/dev/kmsg", "w+");
        fprintf(fd, "<1>urlmount: Successfully connected to %s\n", urls[urlidx]);
        fclose(fd);
    }
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &dldbl);
    downloaded = round(dldbl);
    //Would be needed for multithread
    //curl_easy_cleanup(tmpcurl);
    return downloaded;
}

static int http_open(const char *path, struct fuse_file_info *fi) {
    if (strcmp(path, filename) != 0)
        return -ENOENT;

    if ((fi->flags & 3) != O_RDONLY)
        return -EACCES;

    return 0;
}

static void* http_init(struct fuse_conn_info *conn) {
    // Because we fork, we need to redo curl
    // or else suffer the wrath of NSS TLS
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerror);
    //We want to consider error conditions fatal, rather than
    //passing error text as data
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_URL, urls[urlidx]);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fill_buffer);
    return NULL;
}

static int http_getattr(const char *path, struct stat *st) {
    memset(st, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 2;
    } else if (strcmp(path, filename) == 0) {
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = filesize; // TODO: fix with curl HEAD
    } else
        return -ENOENT;
    return 0;
}


static const struct fuse_operations http_ops = {
    .getattr = http_getattr,
    .readdir = http_readdir,
    .read = http_read,
    .open = http_open,
    .init = http_init,
};

int main(int argc, char* argv[]) {
    char *tmp;
    double fsize;
    unsigned int i;
    int j;
    j = open("/dev/urandom", O_RDONLY);
    if (j <= 0 || read(j, (char*)&i, 4) < 0) {
        i = time(NULL);
    }
    if (j > 0) {
        close(j);
    }
    srand(i);
    j = 0;
    memset(urls, 0, 32*sizeof(char*));
    urlidx = 0;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerror);
    //We want to consider error conditions fatal, rather than
    //passing error text as data
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    memset(filename, 0, MAX_FILE_LEN);
    for (i=0; i < argc; i++) {
        if (strstr(argv[i], ":") > 0) {
            if (j < MAX_URL_PATHS) {
                urls[j] = argv[i];
                tmp = strrchr(urls[j++], '/');
                strncpy(filename, tmp, MAX_FILE_LEN);
            }
            //Request single threaded mode, as curl would need more
            // filehandles for multithread
            argv[i] = "-s";
        }
    }
    if (filename[0] == 0) {
        fprintf(stderr, "No URL given in arguments\n");
        exit(1);
    }
    for (i=0; urls[i] != NULL; i++) {
        printf("Registering mount path: %s\n", urls[i]);
    }
    urlidx = rand() % j;
    j = urlidx;
    printf("Connecting to %s\n", urls[urlidx]);
    curl_easy_setopt(curl, CURLOPT_URL, urls[urlidx]);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    while (curl_easy_perform(curl) != CURLE_OK) {
        fprintf(stderr, "urlmount: error while communicating with %s: %s\n", urls[urlidx++], curlerror);
        if (urls[urlidx] == NULL)
            urlidx = 0;
        if (urlidx == j) {
            fprintf(stderr, "urlmount: Unable to reach any target url, aborting\n");
            exit(1);
        }
        printf("Connecting to %s\n", urls[urlidx]);
        curl_easy_setopt(curl, CURLOPT_URL, urls[urlidx]);
    }
    printf("Successfully connected to %s\n", urls[urlidx]);
    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &fsize);
    filesize = round(fsize);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0);
    if (filesize < 1) {
        fprintf(stderr, "Unable to reach designated URL\n");
        exit(1);
    }
    if (!curl) {
        fprintf(stderr, "Unable to initialize CURL!\n");
        exit(1);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    fuse_main(argc, argv, &http_ops, NULL);
}