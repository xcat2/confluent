#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>

int add_uuid(char* destination, int maxsize) {
    int uuidf;
    int uuidsize;
    uuidf = open("/sys/devices/virtual/dmi/id/product_uuid", O_RDONLY);
    if (uuidf < 1) { return 0; }
    strncpy(destination, "/uuid=", maxsize);
    uuidsize = read(uuidf, destination + 6, maxsize - 6);
    close(uuidf);
    if (destination[uuidsize + 5] == '\n') {
        destination[uuidsize + 5 ] = 0;
    }
    return  uuidsize + 6;
}

int add_macs(char* destination, int maxsize) {
    struct ifaddrs *ifc, *ifa;
    struct sockaddr_ll *lla;
    int offset;
    char macaddr[32];

    offset = 0;
    getifaddrs(&ifa);
    for (ifc = ifa; ifc != NULL; ifc = ifc->ifa_next) {
        if (ifc->ifa_addr->sa_family != AF_PACKET)
            continue;
        lla = (struct sockaddr_ll *)ifc->ifa_addr;
        if (lla->sll_hatype == ARPHRD_INFINIBAND) {
            snprintf(macaddr, 32, "/mac=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                lla->sll_addr[12], lla->sll_addr[13], lla->sll_addr[14],
                lla->sll_addr[15], lla->sll_addr[16], lla->sll_addr[17],
                lla->sll_addr[18], lla->sll_addr[19]
            );
        } else if (lla->sll_hatype == ARPHRD_ETHER) {
            snprintf(macaddr, 32, "/mac=%02x:%02x:%02x:%02x:%02x:%02x",
                lla->sll_addr[0], lla->sll_addr[1], lla->sll_addr[2],
                lla->sll_addr[3], lla->sll_addr[4], lla->sll_addr[5],
                lla->sll_addr[6]
            );
        } else {
            continue;
        }
        strncpy(destination + offset, macaddr, maxsize - offset);
        offset += strnlen(macaddr, 32);
    }
    freeifaddrs(ifa);
}

int main(int argc, char* argv[]) {
    struct ifaddrs *ifc, *ifa;
    struct sockaddr_in6 *in6;
    struct sockaddr_in *in, *bin;
    int ns, n4;
    struct sockaddr_in6 addr, dst;
    struct sockaddr_in addr4, dst4;
    char msg[1024];
    char *nodenameidx;
    char nodename[1024];
    char lastnodename[1024];
    char lastmsg[1024];
    char last6msg[1024];
    int ifidx, offset;
    fd_set rfds;
    struct timeval tv;
    int settime = 0;
    socklen_t dstsize, dst4size;
    dstsize = sizeof(dst);
    dst4size = sizeof(dst4);

    memset(msg, 0, 1024);
    memset(&addr, 0, sizeof(addr));
    memset(&dst, 0, sizeof(dst));
    memset(&dst4, 0, sizeof(dst4));
    memset(nodename, 0, 1024);
    memset(lastnodename, 0, 1024);
    memset(lastmsg, 0, 1024);
    memset(last6msg, 0, 1024);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(190);
    addr4.sin_family = AF_INET;
    addr4.sin_addr.s_addr = htonl(INADDR_ANY);
    addr4.sin_port = htons(190);
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(1900);
    inet_pton(AF_INET6, "ff02::c", &dst.sin6_addr);
    dst4.sin_family = AF_INET;
    dst4.sin_port = htons(1900);
    inet_pton(AF_INET, "239.255.255.250", &dst4.sin_addr);
    strncpy(msg,  "M-SEARCH * HTTP/1.1\r\nST: urn:xcat.org:service:confluent:", 1024);
    offset = strnlen(msg, 1024);
    add_uuid(msg + offset, 1024 - offset);
    offset = strnlen(msg, 1024);
    add_macs(msg + offset, 1024 - offset);
    offset = strnlen(msg, 1024);
    ns = socket(AF_INET6, SOCK_DGRAM, 0);
    n4 = socket(AF_INET, SOCK_DGRAM, 0);
    ifidx = 1; /* reuse ifidx because it's an unused int here */
    setsockopt(n4, SOL_SOCKET, SO_BROADCAST, &ifidx, sizeof(ifidx));
    setsockopt(ns, IPPROTO_IPV6, IPV6_V6ONLY, &ifidx, sizeof(ifidx));
    /* For now, bind to 190 to prove we are a privileged process */
    bind(n4, (const struct sockaddr *)&addr4, sizeof(addr4));
    bind(ns, (const struct sockaddr *)&addr, sizeof(addr));
    getifaddrs(&ifa);
    for (ifc = ifa; ifc != NULL; ifc = ifc->ifa_next) {
        if (!ifc->ifa_addr) continue;
        if (ifc->ifa_flags & IFF_LOOPBACK) continue;
        if (ifc->ifa_flags & IFF_MULTICAST != IFF_MULTICAST) continue;
        if (ifc->ifa_addr->sa_family == AF_INET6) {
            in6 = (struct sockaddr_in6 *)ifc->ifa_addr;
            if (in6->sin6_scope_id == 0)
                continue;
            ifidx = in6->sin6_scope_id;
            setsockopt(ns, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx));
            sendto(ns, msg, strnlen(msg, 1024), 0, (const struct sockaddr *)&dst, sizeof(dst));
        } else if (ifc->ifa_addr->sa_family == AF_INET) {
            in = (struct sockaddr_in *)ifc->ifa_addr;
            bin = (struct sockaddr_in *)ifc->ifa_ifu.ifu_broadaddr;
            bin->sin_port = htons(1900);
            setsockopt(n4, IPPROTO_IP, IP_MULTICAST_IF, &in->sin_addr, sizeof(in->sin_addr));
            sendto(n4, msg, strnlen(msg, 1024), 0, (const struct sockaddr *)&dst4, sizeof(dst4));
            sendto(n4, msg, strnlen(msg, 1024), 0, (const struct sockaddr *)bin, sizeof(*bin));
        }
    }
    FD_ZERO(&rfds);
    FD_SET(n4, &rfds);
    FD_SET(ns, &rfds);
    tv.tv_sec = 2;
    tv.tv_usec = 500000;
    ifidx = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
    while (ifidx) {
        if (ifidx == -1) perror("Unable to select");
        if (ifidx) {
            if (FD_ISSET(n4, &rfds)) {
                memset(msg, 0, 1024);
                /* Deny packet access to the last 24 bytes to assure null */
                recvfrom(n4, msg, 1000, 0, (struct sockaddr *)&dst4, &dst4size);
                if  (nodenameidx = strstr(msg, "NODENAME: ")) {
                        nodenameidx += 10;
                        strncpy(nodename, nodenameidx, 1024);
                        nodenameidx = strstr(nodename, "\r");
                        if (nodenameidx) { nodenameidx[0] = 0; }
                        if (strncmp(lastnodename, nodename, 1024) != 0) {
                            printf("NODENAME: %s\n", nodename);
                            strncpy(lastnodename, nodename, 1024);
                        }
                }
                if (nodenameidx = strstr(msg, "CURRTIME: ")) {
                    nodenameidx += 10;
                    strncpy(nodename, nodenameidx, 1024);
                    if (nodenameidx = strstr(nodename, "\r")) {
                        nodenameidx[0] = 0;
                    }
                    settime = strtol(nodename, NULL, 10);
                }
                memset(msg, 0, 1024);
                inet_ntop(dst4.sin_family, &dst4.sin_addr, msg, dst4size);
                /* Take measure from printing out the same ip twice in a row */
                if (strncmp(lastmsg, msg, 1024) != 0) {
                    sendto(n4, "PING", 4, 0, (const struct sockaddr *)&dst4, dst4size);
                    printf("MANAGER: %s\n", msg);
                    strncpy(lastmsg, msg, 1024);
                }
            }
            if (FD_ISSET(ns, &rfds)) {
                memset(msg, 0, 1024);
                /* Deny packet access to the last 24 bytes to assure null */
                recvfrom(ns, msg, 1000, 0, (struct sockaddr *)&dst, &dstsize);
                if  (nodenameidx = strstr(msg, "NODENAME: ")) {
                        nodenameidx += 10;
                        strncpy(nodename, nodenameidx, 1024);
                        nodenameidx = strstr(nodename, "\r");
                        if (nodenameidx) { nodenameidx[0] = 0; }
                        if (strncmp(lastnodename, nodename, 1024) != 0) {
                            printf("NODENAME: %s\n", nodename);
                            strncpy(lastnodename, nodename, 1024);
                        }
                }
                if (nodenameidx = strstr(msg, "CURRTIME: ")) {
                    nodenameidx += 10;
                    strncpy(nodename, nodenameidx, 1024);
                    if (nodenameidx = strstr(nodename, "\r")) {
                        nodenameidx[0] = 0;
                    }
                    settime = strtol(nodename, NULL, 10);
                }
                memset(msg, 0, 1024);
                inet_ntop(dst.sin6_family, &dst.sin6_addr, msg, dstsize);
                if (strncmp(last6msg, msg, 1024) != 0) {
                    sendto(ns, "PING", 4, 0, (const struct sockaddr *)&dst, dstsize);
                    printf("MANAGER: %s", msg);
                    if (strncmp(msg, "fe80::", 6) == 0) {
                        printf("%%%u", dst.sin6_scope_id);
                    }
                    printf("\n");
                    strncpy(last6msg, msg, 1024);
                }
            }
        }
        if (settime && argc > 1 && strcmp(argv[1], "-t") == 0) {
            tv.tv_sec = settime;
            settimeofday(&tv, NULL);
            settime = 0;
        }
        tv.tv_sec = 0;
        FD_SET(n4, &rfds);
        FD_SET(ns, &rfds);
        ifidx = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
    }
}
