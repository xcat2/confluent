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
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <math.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

CURL *curl;

char curlerror[CURL_ERROR_SIZE];
char recheckerror[CURL_ERROR_SIZE];
curl_off_t filesize;

typedef struct downloadbuffer {
    char *response;
    size_t completed;
    size_t total;
} downloadbuffer;

#define MAX_FILE_LEN 1024
#define MAX_URL_PATHS 512
static char filename[MAX_FILE_LEN + 1];
static int urlidx, newidx;
static char* urls[MAX_URL_PATHS + 1];
static pthread_mutex_t url_state_lock = PTHREAD_MUTEX_INITIALIZER;


static void log_status(const char *priority, const char *fmt, ...) {
    va_list ap;
    FILE *fd = fopen("/dev/kmsg", "w+");

    if (fd == NULL)
        fd = stderr;

    fprintf(fd, "%surlmount: ", priority);
    va_start(ap, fmt);
    vfprintf(fd, fmt, ap);
    va_end(ap);
    fprintf(fd, "\n");

    if (fd != stderr)
        fclose(fd);
}


void *http_rechecker(void *argp) {
    CURL *checkurl;
    int current_newidx;
    int current_urlidx;
    int tmpidx, tmpval;

    (void)argp;
    tmpidx = open("/dev/urandom", O_RDONLY);
    if (tmpidx <= 0 || read(tmpidx, (char*)&tmpval, 4) < 0)
        tmpval = time(NULL) & 0xffffffff;
    if (tmpidx >= 0)
        close(tmpidx);
    srand(tmpval);
    checkurl = curl_easy_init();
    if (checkurl == NULL) {
        fprintf(stderr, "Unable to initialize CURL for rechecker\n");
        return NULL;
    }
    if (curl_easy_setopt(checkurl, CURLOPT_ERRORBUFFER, recheckerror) != CURLE_OK) {
        fprintf(stderr, "Error buffer\n");
        exit(1);
    }
    //We want to consider error conditions fatal, rather than
    //passing error text as data
    if (curl_easy_setopt(checkurl, CURLOPT_FAILONERROR, 1L) != CURLE_OK) {
        fprintf(stderr, "Fail on error\n");
        exit(1);
    }
    if (curl_easy_setopt(checkurl, CURLOPT_TIMEOUT, 10L) != CURLE_OK) {
        fprintf(stderr, "Error setting timeout\n");
        exit(1);
    }
    if (curl_easy_setopt(checkurl, CURLOPT_NOBODY, 1) != CURLE_OK) {
        fprintf(stderr, "Error setting nobody\n");
        exit(1);
    }
    while (1) {
        sleep(25 + tmpval % 10);  // Spread out retries across systems

        pthread_mutex_lock(&url_state_lock);
        current_urlidx = urlidx;
        current_newidx = newidx;
        pthread_mutex_unlock(&url_state_lock);

        tmpidx = 0;
        while (tmpidx < current_urlidx && tmpidx < current_newidx && urls[tmpidx] != NULL) {
            if (curl_easy_setopt(checkurl, CURLOPT_URL, urls[tmpidx]) != CURLE_OK) {
                tmpidx++;
                continue;
            }
            if (curl_easy_perform(checkurl) == CURLE_OK) {
                pthread_mutex_lock(&url_state_lock);
                newidx = tmpidx;
                pthread_mutex_unlock(&url_state_lock);
                break;
            } else
                tmpidx++;
        }
    }
}

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
    const char *current_url;
    double dldbl = 0.0;
    int startidx;
    int reconnecting = 0;
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

    if (strcmp(path, filename) != 0) return -ENOENT;
    memset(headbuffer, 0, 512);
    if (offset >= filesize || size == 0) return 0;
    if (offset + size > filesize) size = filesize - offset;
    snprintf(headbuffer, 512, "%ld-%ld", offset, offset + size - 1);
    if (curl_easy_setopt(curl, CURLOPT_RANGE, headbuffer) != CURLE_OK) {
        fprintf(stderr, "Error setting range\n");
        exit(1);
    }
    if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&dlbuf) != CURLE_OK) {
        fprintf(stderr, "Error setting writedata\n");
        exit(1);
    }

    pthread_mutex_lock(&url_state_lock);
    startidx = urlidx;
    if (newidx < MAX_URL_PATHS) {
        reconnecting = 1;
        urlidx = newidx;
        newidx = MAX_URL_PATHS;
    }
    current_url = urls[urlidx];
    pthread_mutex_unlock(&url_state_lock);

    if (reconnecting) {
        log_status("<5>", "Connecting to %s", current_url);
        // if fail, carry on and take the error in curl_easy_perform instead
        if (curl_easy_setopt(curl, CURLOPT_URL, current_url) != CURLE_OK) {}
    }

    while (curl_easy_perform(curl) != CURLE_OK) {
        int wrapped;

        reconnecting = 1;
        dlbuf.completed = 0;
        log_status("<4>", "error while communicating with %s: %s", current_url, curlerror);

        pthread_mutex_lock(&url_state_lock);
        urlidx++;
        if (urlidx > MAX_URL_PATHS || urls[urlidx] == NULL)
            urlidx = 0;
        wrapped = (urlidx == startidx);
        current_url = urls[urlidx];
        pthread_mutex_unlock(&url_state_lock);

        if (wrapped) {
            log_status("<1>", "All connections to source are down");
            sleep(10);
        }

        log_status("<5>", "Connecting to %s", current_url);
        if (urlidx > MAX_URL_PATHS) {
            fprintf(stderr, "Maximum url path exceeded\n");
            exit(1);
        }
        // ignore, let the curl_easy_perform get the error
        if (curl_easy_setopt(curl, CURLOPT_URL, current_url) != CURLE_OK) {}
    }
    if (reconnecting) {
        log_status("<5>", "Successfully connected to %s", current_url);
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
    pthread_t tid;

    (void)conn;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    pthread_create(&tid, NULL, http_rechecker, NULL);
    pthread_detach(tid);
    curl = curl_easy_init();
    if (curl == NULL) {
        fprintf(stderr, "Unable to initialize CURL\n");
        exit(1);
    }
    if (curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerror) != CURLE_OK) {
        fprintf(stderr, "Failure initializing libcurl error buffor\n");
        exit(1);
    }
    //We want to consider error conditions fatal, rather than
    //passing error text as data
    if (curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L) != CURLE_OK) {
        fprintf(stderr, "Failure initializing libcurl failonerror\n");
        exit(1);
    }
    if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L) != CURLE_OK) {
        fprintf(stderr, "Failure initializing libcurl timeout\n");
        exit(1);
    }
    if (curl_easy_setopt(curl, CURLOPT_URL, urls[urlidx]) != CURLE_OK) {
        fprintf(stderr, "Failure initializing url\n");
        exit(1);
    }
    if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fill_buffer) != CURLE_OK) {
        fprintf(stderr, "Failure initializing libcurl fill buffer\n");
        exit(1);
    }
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
    j = 0;
    memset(urls, 0, sizeof(urls));
    urlidx = 0;
    newidx = MAX_URL_PATHS;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Unable to initialize CURL!\n");
        exit(1);
    }
    if (curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerror) != CURLE_OK) {
        fprintf(stderr, "Unable to set error buffer\n");
        exit(1);
    }
    //We want to consider error conditions fatal, rather than
    //passing error text as data
    if (curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L) != CURLE_OK) {
        fprintf(stderr, "Unable to set fail on error\n");
        exit(1);
    }
    if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L) != CURLE_OK) {
        fprintf(stderr, "Unable to setup curl timeout\n");
        exit(1);
    }
    memset(filename, 0, sizeof(filename));
    for (i=0; i < argc; i++) {
        if (strstr(argv[i], ":") != NULL) {
            if (j < MAX_URL_PATHS) {
                urls[j] = argv[i];
                tmp = strrchr(urls[j], '/');
                if (tmp == NULL || tmp[1] == '\0') {
                    fprintf(stderr, "URL must include a filename: %s\n", urls[j]);
                    exit(1);
                }
                j++;
                strncpy(filename, tmp, MAX_FILE_LEN);
                filename[MAX_FILE_LEN] = '\0';
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
    j = urlidx;
    printf("Connecting to %s\n", urls[urlidx]);
    if (curl_easy_setopt(curl, CURLOPT_URL, urls[urlidx]) != CURLE_OK) {
        fprintf(stderr, "Unable to set url\n");
    }
    if (curl_easy_setopt(curl, CURLOPT_NOBODY, 1) != CURLE_OK) {
        fprintf(stderr, "Failure setting no body\n");
    }
    while (curl_easy_perform(curl) != CURLE_OK) {
        fprintf(stderr, "urlmount: error while communicating with %s: %s\n", urls[urlidx++], curlerror);
        if (urls[urlidx] == NULL)
            urlidx = 0;
        if (urlidx == j) {
            fprintf(stderr, "urlmount: Unable to reach any target url, aborting\n");
            exit(1);
        }
        printf("Connecting to %s\n", urls[urlidx]);
        if (curl_easy_setopt(curl, CURLOPT_URL, urls[urlidx]) != CURLE_OK) {
            fprintf(stderr, "Unable to set url\n");
        }
    }
    printf("Successfully connected to %s\n", urls[urlidx]);
    if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &fsize) != CURLE_OK) {
        fprintf(stderr, "Failed getting content length\n");
        exit(1);
    }
    filesize = round(fsize);
    if (curl_easy_setopt(curl, CURLOPT_NOBODY, 0) != CURLE_OK) {
        fprintf(stderr, "Failed setting nobody\n");
        exit(1);
    }
    if (filesize < 1) {
        fprintf(stderr, "Unable to reach designated URL\n");
        exit(1);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    fuse_main(argc, argv, &http_ops, NULL);
}
