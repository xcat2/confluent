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
    int ifidx, offset;
    socklen_t dstsize, dst4size;
    dstsize = sizeof(dst);
    dst4size = sizeof(dst4);

    memset(msg, 0, 1024);
    memset(&addr, 0, sizeof(addr));
    memset(&dst, 0, sizeof(dst));
    memset(&dst4, 0, sizeof(dst4));
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
    if (argc > 1) {
        snprintf(msg + offset, 1024 - offset, "/node=%s", argv[1]);
        offset = strnlen(msg, 1024);
    }
    add_uuid(msg + offset, 1024 - offset);
    offset = strnlen(msg, 1024);
    add_macs(msg + offset, 1024 - offset);
    offset = strnlen(msg, 1024);
    ns = socket(AF_INET6, SOCK_DGRAM, 0);
    n4 = socket(AF_INET, SOCK_DGRAM, 0);
    ifidx = 1;
    setsockopt(n4, SOL_SOCKET, SO_BROADCAST, &ifidx, sizeof(ifidx));
    setsockopt(ns, IPPROTO_IPV6, IPV6_V6ONLY, &ifidx, sizeof(ifidx));
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
    recvfrom(ns, msg, 1024, 0, (struct sockaddr *)&dst, &dstsize);
    inet_ntop(dst.sin6_family, &dst.sin6_addr, msg, dstsize);
    printf(msg);
}
