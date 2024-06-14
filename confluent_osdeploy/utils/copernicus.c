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

typedef struct sockaddr_llib {
    unsigned short int sll_family;
    unsigned short int sll_protocol;
    int sll_ifindex;
    unsigned short int sll_hatype;
    unsigned char sll_pkttype;
    unsigned char sll_halen;
    unsigned char sll_addr[20];
} sockaddr_llib;

int add_uuid(char* destination, int maxsize) {
    int uuidf;
    int uuidsize;
    uuidf = open("/sys/devices/virtual/dmi/id/product_uuid", O_RDONLY);
    if (uuidf < 0) { return 0; }
    strncpy(destination, "/uuid=", maxsize);
    uuidsize = read(uuidf, destination + 6, maxsize - 6);
    close(uuidf);
    if (uuidsize < 0) { return 0; }
    if (uuidsize > 524288) { return 0; }
    if (destination[uuidsize + 5] == '\n') {
        destination[uuidsize + 5 ] = 0;
    }
    return  uuidsize + 6;
}

int add_confluent_uuid(char* destination, int maxsize) {
    int uuidf;
    int uuidsize;
    uuidf = open("/confluent_uuid", O_RDONLY);
    if (uuidf < 0) { return 0; }
    strncpy(destination, "/confluentuuid=", maxsize);
    uuidsize = read(uuidf, destination + 15, maxsize - 15);
    close(uuidf);
    if (uuidsize < 0) { return 0; }
    if (uuidsize > 524288) { return 0; }
    if (destination[uuidsize + 14] == '\n') {
        destination[uuidsize + 14] = 0;
    }
    return uuidsize + 15;
}

void add_macs(char* destination, int maxsize) {
    struct ifaddrs *ifc, *ifa;
    struct sockaddr_llib *lla;
    int offset;
    char macaddr[32];

    offset = 0;
    getifaddrs(&ifa);
    for (ifc = ifa; ifc != NULL; ifc = ifc->ifa_next) {
        if (ifc->ifa_addr->sa_family != AF_PACKET)
            continue;
        lla = (struct sockaddr_llib *)ifc->ifa_addr;
        if (lla->sll_hatype == ARPHRD_INFINIBAND) {
            snprintf(macaddr, 32, "/mac=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                lla->sll_addr[12], lla->sll_addr[13], lla->sll_addr[14],
                lla->sll_addr[15], lla->sll_addr[16], lla->sll_addr[17],
                lla->sll_addr[18], lla->sll_addr[19]
            );
        } else if (lla->sll_hatype == ARPHRD_ETHER) {
            snprintf(macaddr, 32, "/mac=%02x:%02x:%02x:%02x:%02x:%02x",
                lla->sll_addr[0], lla->sll_addr[1], lla->sll_addr[2],
                lla->sll_addr[3], lla->sll_addr[4], lla->sll_addr[5]
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
    unsigned int lastidx = 2147483648;
    struct sockaddr_in6 addr, dst;
    struct sockaddr_in addr4, dst4;
    char msg[1024];
    char *nodenameidx;
    char nodename[1024];
    char lastnodename[1024];
    char lastmsg[1024];
    char last6msg[1024];
    char mgtifname[1024];
    int ifidx, offset, isdefault;
    fd_set rfds;
    struct timeval tv;
    int settime = 0;
    int setusec = 500000;
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
    if (argc > 1 && strcmp(argv[1], "-a") == 0) {
        strncpy(msg + offset, "/allconfluent=1", 1024 - offset);
        offset = strnlen(msg, 1024);
    }
    add_confluent_uuid(msg + offset, 1024 - offset);
    offset = strnlen(msg, 1024);
    add_uuid(msg + offset, 1024 - offset);
    offset = strnlen(msg, 1024);
    add_macs(msg + offset, 1024 - offset);
    offset = strnlen(msg, 1024);
    ns = socket(AF_INET6, SOCK_DGRAM, 0);
    n4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (ns < 0) {
        fprintf(stderr, "Error opening IPv6 socket\n");
        exit(1);
    }
    if (n4 < 0) {
        fprintf(stderr, "Error opening IPv4 socket\n");
        exit(1);
    }
    ifidx = 1; /* reuse ifidx because it's an unused int here */
    if (setsockopt(n4, SOL_SOCKET, SO_BROADCAST, &ifidx, sizeof(ifidx)) != 0) {
        fprintf(stderr, "Unable to set broadcast on socket\n");
    }
    if (setsockopt(ns, IPPROTO_IPV6, IPV6_V6ONLY, &ifidx, sizeof(ifidx)) != 0) {
        fprintf(stderr, "Unable to limit socket to IPv6 only\n");
    }
    /* For now, bind to 190 to prove we are a privileged process */
    if (bind(n4, (const struct sockaddr *)&addr4, sizeof(addr4)) < 0) {
        fprintf(stderr, "Error binding privilged port!\n");
        exit(1);
    }
    if (bind(ns, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Error binding ipv6 privileged port!\n");
        exit(1);
    }
    getifaddrs(&ifa);
    for (ifc = ifa; ifc != NULL; ifc = ifc->ifa_next) {
        if (!ifc->ifa_addr) continue;
        if (ifc->ifa_flags & IFF_LOOPBACK) continue;
        if ((ifc->ifa_flags & IFF_MULTICAST) != IFF_MULTICAST) continue;
        if (ifc->ifa_addr->sa_family == AF_INET6) {
            in6 = (struct sockaddr_in6 *)ifc->ifa_addr;
            if (in6->sin6_scope_id == 0)
                continue;
            ifidx = in6->sin6_scope_id;
            if (setsockopt(ns, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx)) != 0)
                continue;
            if (sendto(ns, msg, strnlen(msg, 1024), 0, (const struct sockaddr *)&dst, sizeof(dst)) < 0) {
                continue;
            }
        } else if (ifc->ifa_addr->sa_family == AF_INET) {
            in = (struct sockaddr_in *)ifc->ifa_addr;
            bin = (struct sockaddr_in *)ifc->ifa_ifu.ifu_broadaddr;
            bin->sin_port = htons(1900);
            if (setsockopt(n4, IPPROTO_IP, IP_MULTICAST_IF, &in->sin_addr, sizeof(in->sin_addr)) != 0)
                continue;
            if (sendto(n4, msg, strnlen(msg, 1024), 0, (const struct sockaddr *)&dst4, sizeof(dst4)) < 0) {
                // ignore failure to send, we are trying to be opportunistic
            }
            if (sendto(n4, msg, strnlen(msg, 1024), 0, (const struct sockaddr *)bin, sizeof(*bin)) < 0) {
                continue;
            }
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
            mgtifname[0] = 0;
            isdefault = 0;
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
                if (nodenameidx = strstr(msg, "CURRMSECS: ")) {
                    nodenameidx += 10;
                    strncpy(nodename, nodenameidx, 1024);
                    if (nodenameidx = strstr(nodename, "\r")) {
                        nodenameidx[0] = 0;
                    }
                    setusec = strtol(nodename, NULL, 10) * 1000;
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
                if (nodenameidx = strstr(msg, "DEFAULTNET: 1")) {
                    isdefault = 1;
                }
                if (nodenameidx = strstr(msg, "MGTIFACE: ")) {
                    nodenameidx += 10;
                    strncpy(mgtifname, nodenameidx, 1024);
                    if (nodenameidx = strstr(mgtifname, "\r")) {
                        nodenameidx[0] = 0;
                    }
                }
                if (nodenameidx = strstr(msg, "CURRMSECS: ")) {
                    nodenameidx += 10;
                    strncpy(nodename, nodenameidx, 1024);
                    if (nodenameidx = strstr(nodename, "\r")) {
                        nodenameidx[0] = 0;
                    }
                    setusec = strtol(nodename, NULL, 10) * 1000;
                }
                memset(msg, 0, 1024);
                inet_ntop(dst.sin6_family, &dst.sin6_addr, msg, dstsize);
                if (strncmp(last6msg, msg, 1024) != 0 || lastidx != dst.sin6_scope_id) {
		    lastidx = dst.sin6_scope_id;
                    sendto(ns, "PING", 4, 0, (const struct sockaddr *)&dst, dstsize);
                    printf("MANAGER: %s", msg);
                    if (strncmp(msg, "fe80::", 6) == 0) {
                        printf("%%%u", dst.sin6_scope_id);
                    }
                    printf("\n");
                    printf("EXTMGRINFO: %s", msg);
                    if (strncmp(msg, "fe80::", 6) == 0) {
                        printf("%%%u", dst.sin6_scope_id);
                    }
                    printf("|%s|%d\n", mgtifname, isdefault);
                    strncpy(last6msg, msg, 1024);
                }
            }
        }
        if (settime && argc > 1 && strcmp(argv[1], "-t") == 0) {
            tv.tv_sec = settime;
            tv.tv_usec = setusec;
            settimeofday(&tv, NULL);
            settime = 0;
        }
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        FD_SET(n4, &rfds);
        FD_SET(ns, &rfds);
        ifidx = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
    }
}
