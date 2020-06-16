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

/* must < 1E9 or 1s */
#define DELAY_NS 10000

#define TCP_W_OPT_LEN_WORD_MIN 5
#define PPT_H_SIZE_WORD 3
#define PPT_H_SIZE (PPT_H_SIZE_WORD << 2)
/* use experimental tcp option kind */
#define PPT_H_KIND 254
/* network byte order */
#define PPT_H_EXID 0x0000
#define PPT_H_ONLY (PPT_H_KIND | PPT_H_SIZE << 8 | PPT_H_EXID << 16)


static bool volatile keep_running = true;
static __u64 start_time, end_time;
static struct timespec time_now;
static const struct timeval recv_timeout = {1, 0};
static int sock_raw;


struct ppthdr
{
    __u32 header;
    __u64 tstamp;
} __attribute__((packed));

void int_handler(int dummy)
{
    keep_running = 0;
    close(sock_raw);
}

__u64 get_now_ns()
{
    if (clock_gettime(CLOCK_MONOTONIC, &time_now) < 0)
    {
        perror("clock_gettime()");
        exit(1);
    }

    return ( ((__u64)(time_now.tv_sec))*1E9 + time_now.tv_nsec );
}


int main()
{
    const int one = 1;
    int recv_size, sent_size;
    struct sockaddr_ll sa;
    unsigned char buffer[IP_MAXPACKET];
    struct iphdr *ip = (struct iphdr *) (buffer);
    struct tcphdr *tcp = (struct tcphdr *) \
                        (buffer + sizeof(*ip));
    struct ppthdr *ppt = (struct ppthdr *) \
                        (buffer + sizeof(*ip) + sizeof(*tcp));

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
    sa.sll_addr[3] = 0x82;
    sa.sll_addr[4] = 0x6c;
    sa.sll_addr[5] = 0x54;
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

        start_time = get_now_ns();
        end_time = 0;

        while(end_time < start_time + DELAY_NS)
        {
            end_time = get_now_ns();
        }


        /* Send the same packet out */
        sent_size = sendto(sock_raw, buffer, recv_size,
                            MSG_DONTWAIT | MSG_DONTROUTE,
                           (struct sockaddr*) &sa, sizeof(sa));
        if (sent_size < 0) {
            perror("sendto() error");
            exit(1);
        }

        end_time = get_now_ns();

        if ((ip->protocol == IPPROTO_TCP) &&
            (tcp->doff > TCP_W_OPT_LEN_WORD_MIN) &&
            (ppt->header == PPT_H_ONLY))
        {
            /* get time now again to also count the sending time */
            printf("ppt: %llu\n", end_time - start_time);
        }

        // printf("%llu\n", end_time - start_time);

    }
    close(sock_raw);
    return 0;
}
