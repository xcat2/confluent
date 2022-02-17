#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>
#include "tmt.h"
#define HASHSIZE 2053
#define MAXNAMELEN 256
#define MAXDATALEN 8192
struct terment {
    struct terment *next;
    char *name;
    TMT *vt;
};

#define SETNODE 1
#define WRITE 2
#define READBUFF 0
static struct terment *buffers[HASHSIZE];

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

TMT *set_termentbyname(char *name) {
    struct terment *ret;
    int idx;

    idx = hash(name);
    for (ret = buffers[idx]; ret != NULL; ret = ret->next)
        if (strcmp(name, ret->name) == 0)
            return ret->vt;
    ret = (struct terment *)malloc(sizeof(*ret));
    ret->next = buffers[idx];
    ret->name = strdup(name);
    ret->vt = tmt_open(31, 100, NULL, NULL, L"→←↑↓■◆▒°±▒┘┐┌└┼⎺───⎽├┤┴┬│≤≥π≠£•");
    buffers[idx] = ret;
    return ret->vt;
}

void dump_vt(TMT* outvt) {
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
    size_t srgidx = 0;
    char colorcode = 0;
    wprintf(L"\033c");
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
                wprintf(L"\033[%lsm", sgrline);
            }
            wprintf(L"%lc", out->lines[line]->chars[idx].c);
        }
        if (line < maxrow)
            wprintf(L"\r\n");
    }
    fflush(stdout);
    wprintf(L"\x1b[%ld;%ldH", curs->r + 1, curs->c + 1);
    fflush(stdout);
}

int main(int argc, char* argv[]) {
    int cmd, length;
    setlocale(LC_ALL, "");
    char cmdbuf[MAXDATALEN];
    char currnode[MAXNAMELEN];
    TMT *currvt = NULL;
    TMT *outvt = NULL;
    stdin = freopen(NULL, "rb", stdin);
    if (stdin == NULL) {
        exit(1);
    }
    while (1) {
        length = fread(&cmd, 4, 1, stdin);
        if (length < 0)
            continue;
        length = cmd & 536870911;
        cmd = cmd >> 29;
        if (cmd == SETNODE) {
            cmd = fread(currnode, 1, length, stdin);
            currnode[length] = 0;
            if (cmd < 0)
                continue;
            currvt = set_termentbyname(currnode);
        } else if (cmd == WRITE) {
            if (currvt == NULL)
                currvt = set_termentbyname("");
            cmd = fread(cmdbuf, 1, length, stdin);
            cmdbuf[length] = 0;
            if (cmd < 0)
                continue;
            tmt_write(currvt, cmdbuf, length);
        } else if (cmd == READBUFF) {
            cmd = fread(cmdbuf, 1, length, stdin);
            cmdbuf[length] = 0;
            if (cmd < 0)
                continue;
            outvt = get_termentbyname(cmdbuf);
            if (outvt != NULL)
                dump_vt(outvt);
            length = write(1, "\x00", 1);
            if (length < 0)
                continue;
        }
    }
}
