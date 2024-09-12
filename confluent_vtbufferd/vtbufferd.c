#include <asm-generic/socket.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <fcntl.h>
#include "tmt.h"
#define HASHSIZE 2053
#define MAXNAMELEN 256
#define MAXDATALEN 8192
struct terment {
    struct terment *next;
    char *name;
    int fd;
    TMT *vt;
};

#define SETNODE 1
#define WRITE 2
#define READBUFF 0
#define CLOSECONN 3
#define MAXEVTS 16
static struct terment *buffers[HASHSIZE];
static char* nodenames[HASHSIZE];

unsigned long hash(char *str)
/* djb2a */
{
    unsigned long idx = 5381;
    int c;

    while ((c = *str++))
        idx = ((idx << 5) + idx) + c;
    return idx % HASHSIZE;
}

TMT *get_termentbyname(char *name) {
    struct terment *ret;
    for (ret = buffers[hash(name)]; ret != NULL; ret = ret->next)
        if (strcmp(name, ret->name) == 0)
            return ret->vt;
    return NULL;
}

TMT *set_termentbyname(char *name, int fd) {
    struct terment *ret;
    int idx;

    if (nodenames[fd] == NULL) {
        nodenames[fd] = strdup(name);
    }
    idx = hash(name);
    for (ret = buffers[idx]; ret != NULL; ret = ret->next)
        if (strcmp(name, ret->name) == 0)
            return ret->vt;
    ret = (struct terment *)malloc(sizeof(*ret));
    ret->next = buffers[idx];
    ret->name = strdup(name);
    ret->fd = fd;
    ret->vt = tmt_open(31, 100, NULL, NULL, L"→←↑↓■◆▒°±▒┘┐┌└┼⎺───⎽├┤┴┬│≤≥π≠£•");
    buffers[idx] = ret;
    return ret->vt;
}

void dump_vt(TMT* outvt, int outfd) {
    const TMTSCREEN *out = tmt_screen(outvt);
    const TMTPOINT *curs = tmt_cursor(outvt);
    int line, idx, maxcol, maxrow;
    bool bold = false;
    bool dim = false;
    bool underline = false;
    bool blink = false;
    bool reverse = false;
    bool invisible = false;
    bool intensitychg = false;
    tmt_color_t fg = TMT_COLOR_DEFAULT;
    tmt_color_t bg = TMT_COLOR_DEFAULT;
    wchar_t sgrline[30];
    char strbuffer[128];
    size_t srgidx = 0;
    char colorcode = 0;
    write(outfd, "\033c", 2);
    maxcol = 0;
    maxrow = 0;
    for (line = out->nline - 1; line >= 0; --line) {
        for (idx = out->ncol - 1; idx > maxcol; --idx) {
            if (out->lines[line]->chars[idx].c != L' ') {
                if (maxrow < line)
                    maxrow = line;
                maxcol = idx;
                break;
            }
        }
    }
    for (line = 0; line <= maxrow; line++) {
        for (idx = 0; idx <= maxcol; idx++) {
            sgrline[0] = L'\x00';
            intensitychg = false;
            if (out->lines[line]->chars[idx].a.bold != bold) {
                bold = out->lines[line]->chars[idx].a.bold;
                intensitychg = true; // Can't unbold without changing dim
            }
            if (out->lines[line]->chars[idx].a.dim != dim) {
                dim = out->lines[line]->chars[idx].a.dim;
                intensitychg = true; // Can't undim without changing bold
            }
            if (intensitychg) {
                intensitychg = false;
                wcscat(sgrline, L"22;");
                if (bold)
                    wcscat(sgrline, L"1;");
                if (dim)
                    wcscat(sgrline, L"2;");
            }
            if (out->lines[line]->chars[idx].a.underline != underline) {
                underline = out->lines[line]->chars[idx].a.underline;
                if (underline)
                    wcscat(sgrline, L"4;");
                else
                    wcscat(sgrline, L"24;");
            }
            if (out->lines[line]->chars[idx].a.blink != blink) {
                blink = out->lines[line]->chars[idx].a.blink;
                if (blink)
                    wcscat(sgrline, L"5;");
                else
                    wcscat(sgrline, L"25;");
            }
            if (out->lines[line]->chars[idx].a.reverse != reverse) {
                reverse = out->lines[line]->chars[idx].a.reverse;
                if (reverse)
                    wcscat(sgrline, L"7;");
                else
                    wcscat(sgrline, L"27;");
            }
            if (out->lines[line]->chars[idx].a.invisible != invisible) {
                invisible = out->lines[line]->chars[idx].a.invisible;
                if (invisible)
                    wcscat(sgrline, L"8;");
                else
                    wcscat(sgrline, L"28;");
            }
            if (out->lines[line]->chars[idx].a.fg != fg) {
                fg = out->lines[line]->chars[idx].a.fg;
                if (fg == TMT_COLOR_DEFAULT)
                    colorcode = 39;
                else
                    colorcode = 29 + fg;
                swprintf(sgrline + wcslen(sgrline), 4, L"%d;", colorcode);
            }
            if (out->lines[line]->chars[idx].a.bg != bg) {
                bg = out->lines[line]->chars[idx].a.bg;
                if (bg == TMT_COLOR_DEFAULT)
                    colorcode = 49;
                else
                    colorcode = 39 + bg;
                swprintf(sgrline + wcslen(sgrline), 4, L"%d;", colorcode);
            }
            if (sgrline[0] != 0) {
                sgrline[wcslen(sgrline) - 1] = 0;  // Trim last ;

                snprintf(strbuffer, sizeof(strbuffer), "\033[%lsm", sgrline);
                write(outfd, strbuffer, strlen(strbuffer));
                write(outfd, "\033[]", 3);
            }
            snprintf(strbuffer, sizeof(strbuffer), "%lc", out->lines[line]->chars[idx].c);
            write(outfd, strbuffer, strlen(strbuffer));
        }
        if (line < maxrow)
            write(outfd, "\r\n", 2);
    }
    //fflush(stdout);
    snprintf(strbuffer, sizeof(strbuffer), "\x1b[%ld;%ldH", curs->r + 1, curs->c + 1);
    write(outfd, strbuffer, strlen(strbuffer));
    //fflush(stdout);
}

int handle_traffic(int fd) {
    int cmd, length;
    char currnode[MAXNAMELEN];
    char cmdbuf[MAXDATALEN];
    char *nodename;
    TMT *currvt = NULL;
    TMT *outvt = NULL;
    length = read(fd, &cmd, 4);
    if (length <= 0) {
        return 0;
    }
    length = cmd & 536870911;
    cmd = cmd >> 29;
    if (cmd == SETNODE) {
        cmd = read(fd, currnode, length);
        currnode[length] = 0;
        if (cmd < 0)
            return 0;
        currvt = set_termentbyname(currnode, fd);
    } else if (cmd == WRITE) {
        if (currvt == NULL) {
            nodename = nodenames[fd];
            currvt = set_termentbyname(nodename, fd);
        }
        cmd = read(fd, cmdbuf, length);
        cmdbuf[length] = 0;
        if (cmd < 0)
            return 0;
        tmt_write(currvt, cmdbuf, length);
    } else if (cmd == READBUFF) {
        cmd = read(fd, cmdbuf, length);
        cmdbuf[length] = 0;
        if (cmd < 0)
            return 0;
        outvt = get_termentbyname(cmdbuf);
        if (outvt != NULL)
            dump_vt(outvt, fd);
        length = write(fd, "\x00", 1);
        if (length < 0)
            return 0;
    } else if (cmd == CLOSECONN) {
        return 0;
    }
    return 1;
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "");
    struct sockaddr_un addr;
    int numevts;
    int status;
    int poller;
    int n, rt;
    socklen_t len;
    int ctlsock = 0;
    int currsock = 0;
    socklen_t addrlen = 0;
    struct ucred ucr;

    struct epoll_event epvt, evts[MAXEVTS];
    stdin = freopen(NULL, "rb", stdin);
    if (stdin == NULL) {
        exit(1);
    }
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path + 1, argv[1], sizeof(addr.sun_path) - 2); // abstract namespace socket
    ctlsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctlsock < 0) {
        perror("Unable to open unix socket - ");
        exit(1);
    }
    status = bind(ctlsock, (const struct sockaddr*)&addr, sizeof(sa_family_t) + strlen(argv[1]) + 1); //sizeof(struct sockaddr_un));
    if (status < 0) {
        perror("Unable to open unix socket - ");
        exit(1);
    }
    listen(ctlsock, 128);
    poller = epoll_create(1);
    memset(&epvt, 0, sizeof(struct epoll_event));
    epvt.events = EPOLLIN;
    epvt.data.fd = ctlsock;
    if (epoll_ctl(poller, EPOLL_CTL_ADD, ctlsock, &epvt) < 0) {
        perror("Unable to poll the socket");
        exit(1);
    }
    // create a unix domain socket for accepting, each connection is only allowed to either read or write, not both
    while (1) {
        numevts = epoll_wait(poller, evts, MAXEVTS, -1);
        if (numevts < 0) {
            perror("Failed wait");
            exit(1);
        }
        for (n = 0; n < numevts; ++n) {
            if (evts[n].data.fd == ctlsock) {
                currsock = accept(ctlsock, (struct sockaddr *) &addr, &addrlen);
                len = sizeof(ucr);
                rt = getsockopt(currsock, SOL_SOCKET, SO_PEERCRED, &ucr, &len);
		if (rt < 0) {
			close(currsock);
			continue;
		}
                if (ucr.uid != getuid()) { // block access for other users
                    close(currsock);
                    continue;
                }
                memset(&epvt, 0, sizeof(struct epoll_event));
                epvt.events = EPOLLIN;
                epvt.data.fd = currsock;
                epoll_ctl(poller, EPOLL_CTL_ADD, currsock, &epvt);
            } else {
                if (!handle_traffic(evts[n].data.fd)) {
                    epoll_ctl(poller, EPOLL_CTL_DEL, evts[n].data.fd, NULL);
                    close(evts[n].data.fd);
                    if (nodenames[evts[n].data.fd] != NULL) {
                        free(nodenames[evts[n].data.fd]);
                        nodenames[evts[n].data.fd] = NULL;
                    }
                }
            }
        }
    }
}


