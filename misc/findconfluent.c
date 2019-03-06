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
        if (ifc->ifa_addr->sa_family != PF_PACKET)
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
    int ns;
    struct sockaddr_in6 addr, dst;
    char msg[1024];
    int ifidx, offset;
    socklen_t dstsize;
    dstsize = sizeof(dst);

    memset(msg, 0, 1024);
    memset(&addr, 0, sizeof(addr));
    memset(&dst, 0, sizeof(dst));
    addr.sin6_family = PF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(190);
    dst.sin6_family = PF_INET6;
    dst.sin6_port = htons(1900);
    inet_pton(PF_INET6, "ff02::c", &dst.sin6_addr);
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
    ns = socket(PF_INET6, SOCK_DGRAM, 0);
    bind(ns, (const struct sockaddr *)&addr, sizeof(addr));
    ifidx = 2;
    setsockopt(ns, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx));
    sendto(ns, msg, strlen(msg), 0, (const struct sockaddr *)&dst, sizeof(dst));
    recvfrom(ns, msg, 1024, 0, (struct sockaddr *)&dst, &dstsize);
    inet_ntop(dst.sin6_family, &dst.sin6_addr, msg, dstsize);
    printf(msg);
}
