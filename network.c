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
#include "network.h"

/**
 * Pseudo header for UDP/TCP IPv4 for checksum
 */
struct pseudo_header_ipv4 {
    uint32_t src;
    uint32_t dst;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t len;
};

/**
 * Pseudo header for UDP/TCP IPv6 for checksum
 */
struct pseudo_header_ipv6 {
    uint64_t src[2];
    uint64_t dst[2];
    uint32_t len;
    uint8_t zeroes[3];
    uint8_t protocol;
};

int make_pseudo_header(uint8_t *buffer, struct sockaddr *src, struct sockaddr *dst, uint8_t protocol, uint16_t len);

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
    printf("Socket %d\n", dst_addr->sa_family);
    int sockfd = socket(dst_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    int res = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name));

    if (res < 0) {
        perror("setsockopt");
        return 2;
    }

    struct sockaddr_storage addr;
    memcpy(&addr, dst_addr, dst_addr_len);
    switch (dst_addr->sa_family) {
        case AF_INET:
            ((struct sockaddr_in *)&addr)->sin_port = htons(9); //9 is discard port
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)&addr)->sin6_port = htons(9); //9 is discard port
            break;

        default:
            // Unreachable
            return -3;
    }

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

uint16_t checksum(uint8_t *buf, int buf_len, struct sockaddr *src_addr, struct sockaddr *dst_addr, uint8_t protocol) {
    uint8_t *data = malloc(buf_len + sizeof(struct pseudo_header_ipv6));

    memset(data, 0, buf_len + sizeof(struct pseudo_header_ipv6));

    if (!data) {
        // Out Of Memory
        return 0;
    }

    int pseudo_header_len = make_pseudo_header(data, src_addr, dst_addr, protocol, buf_len);

    memcpy(data + pseudo_header_len, buf, buf_len);

    int size = (pseudo_header_len + buf_len);

    uint32_t sum = 0;
    int i;

    for (i = 0; i < size - 1; i += 2) {
        uint16_t word16 = *(uint16_t *)&data[i];
        sum += word16;
    }
    
    // Handle odd-sized case.
    if (size & 1) {
        uint16_t word16 = (uint8_t)data[i];  // don't sign extend
        sum += word16;
    }
    
    // Add the overflowing (over 16-bit) bits to the 16 value.
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    free(data);
    return (uint16_t)(~sum);
}

int make_pseudo_header(uint8_t *buffer, struct sockaddr *src_addr, struct sockaddr *dst_addr, uint8_t protocol, uint16_t len) {
    switch (src_addr->sa_family) {
        case AF_INET: {
            struct pseudo_header_ipv4 *header = (struct pseudo_header_ipv4 *)buffer;
            header->src = ((struct sockaddr_in *)src_addr)->sin_addr.s_addr;
            header->dst = ((struct sockaddr_in *)dst_addr)->sin_addr.s_addr;
            header->zeroes = 0;
            header->protocol = protocol;
            header->len = htons(len);

            return sizeof(struct pseudo_header_ipv4);
        }

        case AF_INET6: {
            struct sockaddr_in6 *src = src;
            struct sockaddr_in6 *dst = dst;
            struct pseudo_header_ipv6 *header = (struct pseudo_header_ipv6 *)buffer;

            memcpy(header->src, src->sin6_addr.s6_addr, sizeof(header->src));
            memcpy(header->dst, dst->sin6_addr.s6_addr, sizeof(header->dst));
            memset(header->zeroes, 0, sizeof(header->zeroes));
            header->len = len;
            header->protocol = protocol;

            return sizeof(struct pseudo_header_ipv6);
        }

        default:
            // huh????
            return -1;
    }
}
