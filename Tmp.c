/*
 * sCap is simple application for scanning and capturing incoming packets
 * without libcap. sCap uses system sockets to recieve and dump traffic.
 *
 *  Copyright (c) 2015 Sun Dro (a.k.a. 7th Ghost)
 *  Web: http://off-sec.com/ ; E-Mail: kala0x13@gmail.com
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */


#include "stdinc.h"
#include "packet.h"
#include "errex.h"
#include "info.h"
#include "../slog/slog.h"

/* Max size of buffer */
#define MAXMSG 65536


/* Structure of packets */
typedef struct {
    int tcp;
    int udp;
    int icmp;
    int igmp;
    int total;
    int other;
} ScapPackets;


/* Structure of flags */
typedef struct {
    short info;
    short data;
} ScapFlags;


/* Initialize sCap packets */
void init_scap_packets(ScapPackets * scap)
{
    scap->tcp = 0;
    scap->udp = 0;
    scap->icmp = 0;
    scap->igmp = 0;
    scap->total = 0;
    scap->other = 0;
}


/* Initialize sCap flags */
void init_scap_flags(ScapFlags * scfl)
{
    scfl->info = 0;
    scfl->data = 0;
}


/*
 * Read signal. Function handles illegal signals and
 * intertupts program if there is something wrong.
 */
void sig_handler(int sig)
{
    /* Handle signals */
    if (sig == SIGILL || sig == SIGSEGV)
        slog(0, SLOG_ERROR, "Can not process data");

    if (sig == SIGPIPE)
        slog(0, SLOG_ERROR, "Broken Pipe");

    if (sig == SIGINT)
        slog(0, SLOG_LIVE, "Cleanup on exit");

    exit(-1);
}


/*
 * create_socket - Function creates and returns raw socket.
 */
int create_socket()
{
    /* Used variables */
    int sock;

    /* Create raw socket */
    sock = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if (sock < 0)
        exit_prog(1, "Can not create raw socket (requires root)");

    return sock;
}


/*
 * read_scap_packet - Fucntion reads incomming
 * packets and starts packet parsing and hexdump.
 */
void read_scap_packet(ScapPackets * scap,
                    ScapFlags * scfl,
                    unsigned char* buf,
                    int size)
{
    /* Used variables */
    struct iphdr* iph = (struct iphdr*)buf;
    char* out_line;

    /* Get IP header */
    switch (iph->protocol)
    {
        case 1:
            ++scap->icmp;
            break;
        case 2:
            ++scap->igmp;
            break;
        case 6:
            ++scap->tcp;
            if (scfl->info || scfl->data)
                log_tcp(scfl->data, buf, size);
            break;
        case 17:
            ++scap->udp;
            if (scfl->info || scfl->data)
                log_udp(scfl->data, buf, size);
            break;
        default:
            ++scap->other;
            break;
    }

    /* Total packet counter */
    ++scap->total;

    /* Return status in slog format */
    out_line = ret_slog("[LIVE] TCP: %d   UDP: %d   ICMP: %d   IGMP: %d   Other: %d   Total: %d",
        scap->tcp, scap->udp, scap->icmp, scap->igmp, scap->other, scap->total);

    /* Print status */
    printf("%s\r", out_line);
}


/* Parse cli arguments */
static int parse_arguments(int argc, char *argv[], ScapFlags * scfl)
{
    int c;
    while ( (c = getopt(argc, argv, "i1:d1:h1")) != -1) {
        switch (c) {
        case 'i':
            scfl->info = 1;
            break;
        case 'd':
            scfl->data = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
}


int main(int argc, char **argv)
{
    /* Used variables */
    ScapFlags scfl;
    ScapPackets scap;
    unsigned char buf[MAXMSG];
    struct sockaddr addr;
    int sock, data, size;

    /* Read signals */
    signal(SIGPIPE, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGSEGV, sig_handler);
    signal(SIGILL , sig_handler);

    /* Greet */
    greet("sCap");

    /* Initialise scap */
    init_scap_packets(&scap);
    init_scap_flags(&scfl);
    init_slog("scap", "config.cfg", 2);

    /* Parse Commandline Arguments */
    if (parse_arguments(argc, argv, &scfl))
        return 0;

    /* Create raw socket */
    sock = create_socket();

    /* Main loop (never ends) */
    while(1)
    {
        /* Get packet size */
        size = sizeof addr;

        /* Get packet */
        data = recvfrom(sock, buf, sizeof(buf), 0, &addr, (socklen_t *)&size);
        if(data < 0)
        {
            slog(0, SLOG_ERROR, "Can not get packets");
            break;
        }
        else read_scap_packet(&scap, &scfl, buf, data);
    }

    /* Close socket */
    close(sock);

    return 0;
}
