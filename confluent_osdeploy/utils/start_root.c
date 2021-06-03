#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#define __USE_GNU
#include <sched.h>
int main(int argc, char* argv[]) {
    unshare(CLONE_NEWNS);
    mount("/dev", "/sysroot/dev", NULL, MS_MOVE, NULL);
    mount("/proc", "/sysroot/proc", NULL, MS_MOVE, NULL);
    mount("/sys", "/sysroot/sys", NULL, MS_MOVE, NULL);
    mount("/run", "/sysroot/run", NULL, MS_MOVE, NULL);
    if (chdir("/sysroot") < 0) { fprintf(stderr, "Unable to chdir!\n"); }
    mount("/sysroot", "/", NULL, MS_MOVE, NULL);
    if (chroot(".") < 0) { fprintf(stderr, "Failed to chroot!\n"); }
    if (chdir("/") < 0) { fprintf(stderr, "Unable to chdir after chroot!\n"); }
    execl("/sbin/init", "/sbin/init", NULL);
}
