/**
 * @file network.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Implementation for `network.h`
 */

#include "network.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netdb.h>


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
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t len;
    uint8_t zeroes[3];
    uint8_t protocol;
};

int make_pseudo_header(uint8_t *buffer, struct sockaddr *src, struct sockaddr *dst, uint8_t protocol, uint16_t len);

int create_socket(const char *interface, int family, int protocol) {
    int sockfd = socket(family, SOCK_RAW, protocol);

    if (sockfd < 0) {
        perror("ERR create socket");
        return -1;
    }

    /// Set receiving socket non-blocking for using with poll.
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("ERR set non blocking fcntl");
        close(sockfd);
        return -1;
    }

    /// Bind interface to the sockets
    int bind = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));

    if (bind) {
        perror("ERR bind interface setsockopt");
        close(sockfd);
        return -1;
    }

    return sockfd;
}


void set_port(struct sockaddr *addr, uint16_t port) {
    switch (addr->sa_family) {
        case AF_INET:
            ((struct sockaddr_in *)addr)->sin_port = htons(port);
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
            break;

        default:
            break;
    }
}

uint16_t get_port(struct sockaddr *addr) {
    switch (addr->sa_family) {
        case AF_INET:
            return ntohs(((struct sockaddr_in *)addr)->sin_port);

        case AF_INET6:
            return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);

        default:
            return 0;
    }
}


int print_interfaces() {
    struct ifaddrs *ifaddr, *ifa;

    // Array to store interface names
    char interface_names[NI_MAXHOST][IF_NAMESIZE] = {0};
    int num_interfaces = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    // Iterate through the list of interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // Check if the interface has an IPv4 or IPv6 address
        if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6) {
            continue;
        }

        // Check if the interface name is already in the list
        int duplicate = 0;
        for (int i = 0; i < num_interfaces; ++i) {
            if (strcmp(interface_names[i], ifa->ifa_name) == 0) {
                duplicate = 1;
                break;
            }
        }

        // If the interface name is not a duplicate, add it to the list
        if (!duplicate) {
            strncpy(interface_names[num_interfaces], ifa->ifa_name, IF_NAMESIZE - 1);
            interface_names[num_interfaces][IF_NAMESIZE - 1] = '\0';
            num_interfaces++;
        }
    }

    // Print the list of unique interface names
    for (int i = 0; i < num_interfaces; ++i) {
        printf("%s\n", interface_names[i]);
    }

    freeifaddrs(ifaddr);
    return 0;

}

bool is_valid_interface(const char *name) {
    return if_nametoindex(name);
}

int get_interface(const char *interface_name, struct sockaddr *dst_addr, socklen_t dst_addr_len, struct sockaddr_storage *src_addr, socklen_t *src_addr_len) {
    int sockfd = socket(dst_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);

    if (sockfd < 0) {
        perror("ERR getting interface socket");
        return 1;
    }

    int res = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name));

    if (res < 0) {
        perror("ERR getting interface setsockopt");
        close(sockfd);
        return 2;
    }

    struct sockaddr_storage addr;
    memcpy(&addr, dst_addr, dst_addr_len);
    set_port((struct sockaddr *)&addr, 9); // Discard port

    if (connect(sockfd, (struct sockaddr *)&addr, dst_addr_len) < 0) {
        close(sockfd);
        return -1;
    }

    if (getsockname(sockfd, (struct sockaddr *)src_addr, src_addr_len)) {
        close(sockfd);
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
              perror("ERR inet_ntop");
            }
            break;
        }

        case AF_INET6: {
            char ip_address[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *ipv6_address = (struct sockaddr_in6 *)addr;
            if (inet_ntop(AF_INET6, &ipv6_address->sin6_addr, ip_address, INET6_ADDRSTRLEN)) {
              printf("%s", ip_address);
            } else {
              perror("ERR inet_ntop");
            }
            break;
        }

        default:
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
        uint16_t word16 = (uint8_t)data[i];
        sum += word16;
    }
    
    // fold into 16bit number
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
            struct sockaddr_in6 *src = (struct sockaddr_in6 *)src_addr;
            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)dst_addr;
            struct pseudo_header_ipv6 *header = (struct pseudo_header_ipv6 *)buffer;

            memcpy(&header->src, &src->sin6_addr, sizeof(struct in6_addr));
            memcpy(&header->dst, &dst->sin6_addr, sizeof(struct in6_addr));
            memset(header->zeroes, 0, sizeof(header->zeroes));
            header->len = htonl((uint32_t)len);
            header->protocol = protocol;

            return sizeof(struct pseudo_header_ipv6);
        }

        default:
            // huh????
            return -1;
    }
}
