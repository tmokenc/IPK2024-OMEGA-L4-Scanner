/**
 * @file network.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Implementation for `network.h`
 */

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int print_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    
    // Get a list of available network interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Print the list of interfaces
    printf("Available network interfaces:\n");
    pcap_if_t *interface = interfaces;
    while (interface) {
        printf("- %s\n", interface->name);
        interface = interface->next;
    }

    // Free the memory allocated for the interface list
    pcap_freealldevs(interfaces);
    return 0;

}

int get_interface(const char *interface_name, struct sockaddr *dst_addr, socklen_t dst_addr_len, struct sockaddr_storage *src_addr, socklen_t *src_addr_len) {
    int sockfd = socket(dst_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name));

    struct sockaddr_storage addr;
    memcpy(&addr, dst_addr, dst_addr_len);
    ((struct sockaddr_in *)&addr)->sin_port = htons(9); //9 is discard port

    if (connect(sockfd, (struct sockaddr *)&addr, dst_addr_len) < 0) {
        perror("connect");
        return -1;
    }

    if (getsockname(sockfd, (struct sockaddr *)src_addr, src_addr_len)) {
        perror("getsockname");
        return -2;
    }

    close(sockfd);
    return 0;
}

void print_address(struct sockaddr *addr) {
    switch (addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in *ipv4_address = (struct sockaddr_in *)addr;
            char ip_address[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &ipv4_address->sin_addr, ip_address, INET_ADDRSTRLEN)) {
              printf("%s", ip_address);
            } else {
              perror("inet_ntop");
            }
            break;
        }

        case AF_INET6: {
            char ip_address[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *ipv6_address = (struct sockaddr_in6 *)addr;
            if (inet_ntop(AF_INET6, &ipv6_address->sin6_addr, ip_address, INET6_ADDRSTRLEN)) {
              printf("%s", ip_address);
            } else {
              perror("inet_ntop");
            }
            break;
        }

        default:
            // fprintf(stderr, "Unsupported address family\n");
            break;
    }
}

uint16_t checksum(uint16_t *buf, int nwords) {
    unsigned long sum;

    for(sum=0; nwords>0; nwords--) {
        sum += *buf++;
    }

    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}
