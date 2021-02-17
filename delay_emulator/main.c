#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

#include <errno.h>
#include <signal.h>
#include <time.h>

static bool volatile keep_running = true;
static __u64 start_time, end_time;
static struct timespec time_now;
static const struct timeval recv_timeout = {0, 1000};
static int sock_raw;

void int_handler(int dummy)
{
    keep_running = 0;
    close(sock_raw);
}

__u64 get_now_us()
{
    if (clock_gettime(CLOCK_MONOTONIC, &time_now) < 0)
    {
        perror("clock_gettime()");
        exit(1);
    }

    return ( ((__u64)(time_now.tv_sec))*1E9 + time_now.tv_nsec )/1000;
}


int main(int argc, char *argv[])
{
    int opt;
    int delay_us = -1;

    while((opt = getopt(argc, argv, ":d:")) != -1)
    {
        switch(opt)
        {
            case 'd':
                delay_us = atoi(optarg);
                break;
            case '?':
                printf("./delay_emulator -d [DELAY_US]\n");
                exit(1);
        }
    }

    if(delay_us == -1) {
        printf("missing option '-d'\n");
        exit(1);
    }

    int recv_size, sent_size;
    unsigned char buffer[IP_MAXPACKET];
    struct sockaddr_ll sa;

    sock_raw = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        perror("socket() error");
        exit(1);
    }

    /* bind the socket to ens4 */
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_halen = ETH_ALEN;
    sa.sll_addr[0] = 0xfa;
    sa.sll_addr[1] = 0x16;
    sa.sll_addr[2] = 0x3e;
    sa.sll_addr[3] = 0xd5;
    sa.sll_addr[4] = 0xc1;
    sa.sll_addr[5] = 0xf5;
    sa.sll_ifindex = if_nametoindex("ens4");
    if (bind(sock_raw, (struct sockaddr*) &sa, sizeof(sa)) < 0)
    {
        perror("bind failed\n");
        close(sock_raw);
        exit(1);
    }

    /* set socket timeout */
    if (setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO,
                &recv_timeout, sizeof(recv_timeout)) < 0)
    {
        perror("setsockopt()");
        exit(1);
    }

    signal(SIGINT, int_handler);

    while(keep_running)
    {
        recv_size = recv(sock_raw, buffer, IP_MAXPACKET, 0);
        if (recv_size < 0)
        {
            /* just timeout and no pkt recv. continue */
            if(recv_size == -1)
            {
                continue;
            }
            else
            {
                perror("Recv() error");
                break;
            }
        }

        start_time = get_now_us();
        end_time = 0;

        while(end_time < start_time + delay_us)
        {
            end_time = get_now_us();
        }

        /* Send the same packet out */
        sent_size = sendto(sock_raw, buffer, recv_size,
                            MSG_DONTWAIT | MSG_DONTROUTE,
                           (struct sockaddr*) &sa, sizeof(sa));
        if (sent_size < 0) {
            perror("sendto() error");
            exit(1);
        }
        printf("%llu\n", get_now_us() - start_time);
    }
    close(sock_raw);
    return 0;
}
