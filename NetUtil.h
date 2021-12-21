#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>

// Buffer 大小
#define STRING_BUFFER_SIZE 64

// 將位址轉為字串
char* socketAddressToString(const struct sockaddr* data) {
    static char ret[STRING_BUFFER_SIZE];
    if (data->sa_family != AF_INET) {
        return NULL;
    }

    struct sockaddr_in* address = (struct sockaddr_in*) data;
    if (inet_ntop(AF_INET, &address->sin_addr, ret, sizeof (ret)) == NULL) {
        return NULL;
    }
    return ret;
}

// 比較兩位址是否相同
int compareAddress(const struct sockaddr* left, const struct sockaddr* right) {
    return memcmp(&((struct sockaddr_in *) left)->sin_addr, &((struct sockaddr_in *) right)->sin_addr, sizeof (struct in_addr));
}

// 計算 Check Sum
uint16_t calculateCheckSum(uint16_t* packet, const int length) {
    int available = length;
    uint32_t sum = 0;
    uint16_t* data = packet;
    uint16_t ret = 0;

    while (available > 1) {
        sum += *data++;
        available -= 2;
    }

    if (available == 1) {
        *(unsigned char *) (&ret) = *(unsigned char *) data;
        sum += ret;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    ret = ~sum;
    return ret;
}
