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

uint16_t checksum(uint16_t *pseudo_header, int pseudo_header_len, uint16_t *buf, int buf_len) {
    uint16_t *_data = malloc(pseudo_header_len + buf_len);
    uint16_t *data = _data;

    if (!data) {
        // Out of Memory
        return 0;
    }

    memcpy(data, pseudo_header, pseudo_header_len);
    memcpy(data + pseudo_header_len, buf, buf_len);

    uint32_t sum = 0;
    int count = pseudo_header_len + buf_len;

    while (count > 1) {
        sum += *data++;
        count -= 2;
    }

    if (count > 0) {
        sum += ((*data)&htons(0xFF00));
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    free(_data);
    return (uint16_t)(~sum);
}

int make_pseudo_header(uint8_t *buffer, struct sockaddr *src, struct sockaddr *dst, uint8_t protocol, uint32_t len) {
    switch (src->sa_family) {
        case AF_INET: {
            struct pseudo_header_ipv4 *header = (struct pseudo_header_ipv4 *)buffer;
            header->src = ((struct sockaddr_in *)src)->sin_addr.s_addr;
            header->dst = ((struct sockaddr_in *)dst)->sin_addr.s_addr;
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
