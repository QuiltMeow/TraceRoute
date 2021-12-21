#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#include "Bool.h"
#include "NetUtil.h"

// Trace Route 結果代碼
#define TRACE_RESULT_TIMEOUT -2
#define TRACE_RESULT_TTL_EXCEED -1
#define TRACE_RESULT_DONE 0

// Buffer 大小
#define PACKET_BUFFER_SIZE 1500

// ICMP 標頭長度
#define ICMP_HEADER_LENGTH 8

// Trace Route 查詢次數
#define QUERY_COUNT 3

// Trace Route 超時等待時間 (秒)
#define TIMEOUT 3

// ICMP 資料長度大小
#define ICMP_DATA_LENGTH 64

// IPv4 位址長度
#define IP_ADDRESS_LENGTH 4

// ICMP 填充資料
#define ICMP_FILL_DATA 0x2E

// 目標位址
struct sockaddr_in dstAddress;

// 目標位址字串
char* host;

// 發送與接收 Buffer
char sendBuffer[PACKET_BUFFER_SIZE], receiveBuffer[PACKET_BUFFER_SIZE];

// 超時狀態
bool timeoutAlarm;

// 最大 Hop 數
int hop;

// 進程 ID
int netPid;

// Socket 檔案描述符號
int socketFD;

// 超時處理函式
void alarmHandler(const int signal) {
    timeoutAlarm = true;
}

// 接收路由追蹤封包
int receiveTraceRouteICMPPacket(const int sequence, struct timeval* time, struct sockaddr* address, socklen_t* addressLength) {
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = alarmHandler;
    sigaction(SIGALRM, &action, NULL);

    timeoutAlarm = false;
    alarm(TIMEOUT);

    int ret;
    while (true) {
        if (timeoutAlarm) {
            ret = TRACE_RESULT_TIMEOUT;
            break;
        }

        int length = recvfrom(socketFD, receiveBuffer, sizeof (receiveBuffer), 0, address, addressLength);
        if (length < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                perror("接收封包時發生錯誤 ");
                exit(EXIT_FAILURE);
            }
        }

        struct ip* ipHeader = (struct ip *) receiveBuffer;
        int ipHeaderLength = ipHeader->ip_hl << 2;

        char* icmpLocation = receiveBuffer + ipHeaderLength;
        struct icmp* icmpPacket = (struct icmp *) icmpLocation;

        int icmpLength = length - ipHeaderLength;
        if (icmpLength < ICMP_HEADER_LENGTH) {
            continue;
        }

        u_char type = icmpPacket->icmp_type;
        if (type == ICMP_TIMXCEED && icmpPacket->icmp_code == ICMP_TIMXCEED_INTRANS) {
            if (icmpLength < ICMP_HEADER_LENGTH + sizeof (struct ip)) {
                continue;
            }

            char* nestIPLocation = icmpLocation + ICMP_HEADER_LENGTH;
            struct ip* nestIPHeader = (struct ip *) nestIPLocation;

            int nestIPHeaderLength = nestIPHeader->ip_hl << 2;
            if (icmpLength < ICMP_HEADER_LENGTH + nestIPHeaderLength + ICMP_HEADER_LENGTH) {
                continue;
            }

            struct icmp* nestICMP = (struct icmp *) (nestIPLocation + nestIPHeaderLength);
            if (nestICMP->icmp_type == ICMP_ECHO && nestICMP->icmp_code == 0 && nestICMP->icmp_id == netPid && nestICMP->icmp_seq == htons(sequence)) {
                ret = TRACE_RESULT_TTL_EXCEED;
                break;
            }
        } else if (type == ICMP_ECHOREPLY) {
            if (icmpPacket->icmp_id == netPid && icmpPacket->icmp_seq == htons(sequence)) {
                ret = TRACE_RESULT_DONE;
                break;
            }
        }
    }
    alarm(0);

    gettimeofday(time, NULL);
    return ret;
}

// 開始進行路由追蹤
void startTraceRoute() {
    if ((socketFD = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("建立 Socket 時發生錯誤 ");
        exit(EXIT_FAILURE);
    }

    printf("%s (%s) 追蹤最大 %d 跳躍點路由\n", host, inet_ntoa(dstAddress.sin_addr), hop);
    int sequence = 0;
    bool done = false;
    for (int ttl = 1; ttl <= hop && !done; ++ttl) {
        setsockopt(socketFD, IPPROTO_IP, IP_TTL, &ttl, sizeof (int));

        struct sockaddr lastAddress;
        bzero(&lastAddress, sizeof (lastAddress));
        printf("%d", ttl);
        for (int query = 0; query < QUERY_COUNT; ++query) {
            struct icmp* icmpPacket = (struct icmp*) sendBuffer;
            icmpPacket->icmp_code = 0;
            icmpPacket->icmp_id = netPid;
            icmpPacket->icmp_seq = htons(++sequence);
            icmpPacket->icmp_type = ICMP_ECHO;
            memset(icmpPacket->icmp_data, ICMP_FILL_DATA, ICMP_DATA_LENGTH);

            struct timeval sendTime;
            gettimeofday(&sendTime, NULL);

            icmpPacket->icmp_cksum = 0;
            size_t length = ICMP_HEADER_LENGTH + ICMP_DATA_LENGTH;
            icmpPacket->icmp_cksum = calculateCheckSum((u_short *) icmpPacket, length);
            if (sendto(socketFD, sendBuffer, length, 0, (struct sockaddr *) &dstAddress, sizeof (dstAddress)) < 0) {
                perror("發送封包時發生錯誤 ");
                exit(EXIT_FAILURE);
            }

            struct sockaddr address;
            socklen_t addressLength;
            struct timeval receiveTime;
            int response = receiveTraceRouteICMPPacket(sequence, &receiveTime, &address, &addressLength);

            char* addressString = socketAddressToString(&address);
            if (addressString == NULL) {
                --query;
                continue;
            }

            if (response == TRACE_RESULT_TIMEOUT) {
                printf(" *");
            } else {
                char hostName[NI_MAXHOST];
                if (compareAddress(&lastAddress, &address) != 0) {
                    if (getnameinfo(&address, addressLength, hostName, sizeof (hostName), NULL, 0, 0) == 0) {
                        printf(" %s (%s)", hostName, addressString);
                    } else {
                        printf(" %s", addressString);
                    }
                    memcpy(&lastAddress, &address, addressLength);
                }

                if ((receiveTime.tv_usec -= sendTime.tv_usec) < 0) {
                    --receiveTime.tv_sec;
                    receiveTime.tv_usec += 1000 * 1000;
                }
                receiveTime.tv_sec -= sendTime.tv_sec;

                double rtt = receiveTime.tv_sec * (double) 1000 + receiveTime.tv_usec / (double) 1000;
                printf(" %.3f 毫秒", rtt);

                if (response == TRACE_RESULT_DONE) {
                    done = true;
                }
            }
        }
        printf("\n");
    }
}

// 程式入口點
int main(const int argc, char** argv) {
    if (geteuid() != 0) {
        perror("請以 Root 權限執行本程式 ... ");
        return EXIT_FAILURE;
    }
    if (argc < 3) {
        printf("使用方法 : %s [Hop 數] [IP 位址]\n", argv[0]);
        return EXIT_SUCCESS;
    }

    hop = atoi(argv[1]);
    if (hop <= 0) {
        perror("請輸入有效 Hop 數 ");
        return EXIT_FAILURE;
    }
    host = argv[2];

    in_addr_t ipAddress;
    if ((ipAddress = inet_addr(host)) == INADDR_NONE) {
        struct hostent* endPoint;
        if ((endPoint = gethostbyname(host)) == NULL) {
            perror("未知的主機 ");
            return EXIT_FAILURE;
        }

        int ipLength = endPoint->h_length;
        if (ipLength != IP_ADDRESS_LENGTH) {
            perror("無效的 IPv4 位址長度 ");
            return EXIT_FAILURE;
        }
        memmove(&ipAddress, endPoint->h_addr, ipLength);
    }

    bzero(&dstAddress, sizeof (dstAddress));
    dstAddress.sin_family = AF_INET;
    dstAddress.sin_addr.s_addr = ipAddress;

    netPid = htons(getpid());
    startTraceRoute();
    return EXIT_SUCCESS;
}
