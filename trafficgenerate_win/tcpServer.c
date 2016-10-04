/*
 * tcpsnoop - this program listens on a port, accepts TCP transmissions
 * and writes statistics to a file or STDOUT.
 *
 * Copyright (C) 2006 by RenÃ© Pfeiffer <lynx@luchs.at>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Please see the subversion logs for change details.
 * And please note that I haven't coded C since I used my Amiga. :) This is
 * why we have not much functions and stuff everything into main(). Feel free to
 * clean it up (and send me patches).
 *
 * Useful links:
 * http://www.linuxhowtos.org/C_C++/socket.htm
 * ( http://www.linuxprofilm.com/articles/linux-daemon-howto.html )
 * http://wiki.java.net/bin/view/People/DaemonCreation
 * http://www.cprogramming.com/faq/cgi-bin/smartfaq.cgi?id=1044780608&answer=1108255660
 * http://www.enderunix.org/documents/eng/daemon.php
 * http://www.catb.org/~esr/cookbook/helloserver.c
 *
 */

/*
 * Strategy:
 *
 * - bind to a TCP port
 * - prepare statistics output (file or STDOUT)
 * - listen for incoming connections
 * - periodically check tcp_info structure and print interesting value
 *
 * Options:
 *
 * -b amount of bytes we copy from the network to a buffer (reporting, i.e.
 *    printing the parameters of the TCP connection is done after the buffer
 *    is full)
 * -p TCP port
 * -f filename
 * -d daemon mode or not
 * -D debug mode
 *
 */

/*
 * Get the header files we need
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "tcpServer.h"

/*
 * Definitions
 */
const double INFINITY = 1.0/0.0;
const char default_filename[] = DEFAULT_FILENAME;
void createTraffic(int sock, struct sockaddr_in client_address);
void printResults();

/*
 * Globals (we need those for closing/freeing resources from the signal handlers)
 */

/* File descriptor for log file */
FILE *statistics;
struct sockaddr_in tcp_server_address;
pthread_t monitor_thread;  // this is our thread identifier
unsigned short opt_buffer = DEFAULT_BUFFER;
char *tcp_buffer;
struct tcp_info tcp_info;
int tcp_info_length;
//int tcp_socket;
//int tcp_work_socket;
int opt_time = 10;
double on_time = 0;
double off_time = 2;
double opt_interval = 1; // Every 0.1s print results
int chunkSize = 100; // In KB
/* Buffer for reply string */
int reply_size;
char reply_string[REPLY_MAXLENGTH];
long size = 0;

// For performance calculation
double flow_duration = 0;  // in seconds
double data_sent = 0;  // in Mb
double avg_tp = 0; // in Mbps
double actual_time = 0;
int burst_number = 0;
double burst_tp = 0;

/* Structures needed for measuring time intervals */
struct timeval time_start, time_now, time_delta;

void *monitor_function(void *arg)
{
    /* Measure time in order to create time intervals. */
    printf("Starts monitoring.....\n");
    int socket = *(int *) arg;
    //int cwnd_sample = 0;
    struct timeval time_last;
    get_now(&time_last);
    long lastSize = 0;
    double intervalSizeInMb = 0;
    double thisIntervalEnd = 0;
    fprintf(statistics, "%u\n", (unsigned)time(NULL));
    while (1)
    {
        get_now(&time_now);
        if (time_to_seconds(&time_last, &time_now) >= opt_interval)
        {
            long thisIntervalSize = size - lastSize;
            lastSize = size;
            double thisIntervalStart = time_to_seconds(&time_start, &time_last);
            thisIntervalEnd = time_to_seconds(&time_start, &time_now);
            double thisIntervalTime = thisIntervalEnd - thisIntervalStart;
            double thisIntervalSizeInMb = thisIntervalSize / 125000.0;
            intervalSizeInMb += thisIntervalSizeInMb;
            double thisGoodPutInMb = thisIntervalSizeInMb / thisIntervalTime;
            printf("%.1f - %.1f . Data sent: %.1f Mb. Throughput: %.1f Mbps\n", thisIntervalStart,
                    thisIntervalEnd, thisIntervalSizeInMb, thisGoodPutInMb);
            time_last = time_now;
        }

        if (getsockopt(socket, SOL_TCP, TCP_INFO, (void *) &tcp_info,
                (socklen_t *) &tcp_info_length) == 0)
        {
            //if (cwnd_sample != tcp_info.tcpi_snd_cwnd)
            //{
            // tcpi_rtt smoothed round trip time in microsecond
            get_now(&time_now);
            //printf("%.6f %u %u \n", time_to_seconds(&time_start, &time_now),
            // tcp_info.tcpi_snd_cwnd, tcp_info.tcpi_rtt);
            //fprintf(statistics, "%.6f %u %u\n", time_to_seconds(&time_start, &time_now),
            //tcp_info.tcpi_snd_cwnd, tcp_info.tcpi_rtt);
            fprintf(statistics, "%.6f %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
                    time_to_seconds(&time_start, &time_now), tcp_info.tcpi_last_ack_recv,
                    tcp_info.tcpi_last_data_recv, tcp_info.tcpi_snd_cwnd,
                    tcp_info.tcpi_snd_ssthresh, tcp_info.tcpi_rcv_ssthresh, tcp_info.tcpi_rtt,
                    tcp_info.tcpi_rttvar, tcp_info.tcpi_unacked, tcp_info.tcpi_sacked,
                    tcp_info.tcpi_lost, tcp_info.tcpi_retrans, tcp_info.tcpi_fackets,
                    tcp_info.tcpi_reordering);
            if (fflush(statistics) != 0)
            {
                printf("Cannot flush buffers: %s\n", strerror(errno));
            }
            //}
            //cwnd_sample = tcp_info.tcpi_snd_cwnd;
        }
        else
        {
            if (fflush(statistics) != 0)
            {
                printf("Cannot flush buffers: %s\n", strerror(errno));
            }

            double transmitTime = thisIntervalEnd;
            double throughputInMb;
            if (transmitTime != 0)
                throughputInMb = intervalSizeInMb / transmitTime;
            else
                throughputInMb = 0;
            flow_duration = transmitTime;
            data_sent = intervalSizeInMb;
            avg_tp = throughputInMb;
            //printf("Transmission Time: %.1f seconds . Data sent: %.1f Mb. Throughput: %.1f Mbps\n", transmitTime,
            //        intervalSizeInMb, throughputInMb);
            printf("Connection closed, Stop monitoring..\n");
            break;
        }
        usleep(1000);
    }
    return (void *) NULL;
}

/*
 * ---------------------------------------------------------------------------
 * The main part begins here
 */

int main(int argc, char **argv)
{
    /* Options with their defaults */
    char *opt_filename = NULL;
    unsigned short opt_tcp_port = DEFAULT_TCP_PORT;
    int option;
    /* Program logic */
    int client_length;
    struct sockaddr_in client_address;
    int status;
    /* Our process ID and Session ID */

    /* Parse options */
    while ((option = getopt(argc, argv, "t:f:b:k:s:hrp:")) != -1)
    {
        switch (option)
        {
        case 't':
            opt_time = (int) (strtoul(optarg, NULL, 10));
            break;
        case 'b':
            off_time = (double) (strtod(optarg, NULL));
            break;
        case 'k':
            on_time = (double) (strtod(optarg, NULL));
            break;
        case 's':
            chunkSize = (double) (strtod(optarg, NULL));
            break;
        case 'f':
            opt_filename = optarg;
            break;
        case 'h':
            puts("Welcome to tcpsnoop!\\"
                    "Usage: tcpsnoop [-t running time] [-f filename] [-p tcpport]");
            exit(EXIT_SUCCESS);
            break;
        case 'p':
            opt_tcp_port = (unsigned short) (strtoul(optarg, NULL, 10));
            if (opt_tcp_port < 1024)
            {
                fprintf(stderr, "We can't bind to port %u! It is privileged.\n", opt_tcp_port);
                exit(EXIT_FAILURE);
            }
            break;
        }
    }
    if (opt_filename == NULL)
    {
        opt_filename = (char *) default_filename;
    }
    if (access(opt_filename, F_OK) != -1)
    {
        if (remove(opt_filename) == 0)
        {
            //printf("Delete old log file: %s\n", opt_filename);
        }
    }
/*    if ((off_time == 0) ^ (on_time == 0))
    {
        printf("Error in on-off timer setting \n");
        exit(EXIT_FAILURE);
    }*/
    printf("Listen on port %u.\n", opt_tcp_port);
    statistics = fopen(opt_filename, "a+");
    if (statistics == NULL)
    {
        printf("Could not open statistics file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Prepare TCP socket. */
    int tcp_socket = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_socket == -1)
    {
        /* Could not open socket. */
        printf("Could not open TCP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int sendbuff;
    int res = 0;
    int optlen = sizeof(sendbuff);
    sendbuff = 2 * 1024 * 1024;
    res = setsockopt(tcp_socket, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
    res = getsockopt(tcp_socket, SOL_SOCKET, SO_SNDBUF, (void *) &sendbuff, (socklen_t *) &optlen);
    //printf("Send buff: %u\n", sendbuff);
    if (res == -1)
        printf("Error getsockopt two");

    int optval = 1;
    if (setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1)
    {
        printf("Could not set TCP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    else
    {
        /* Bind to any address on local machine */
        tcp_server_address.sin_family = AF_INET;
        tcp_server_address.sin_addr.s_addr = INADDR_ANY;
        tcp_server_address.sin_port = htons(opt_tcp_port);
        memset((void *) &(tcp_server_address.sin_zero), '\0', 8);
        status = bind(tcp_socket, (struct sockaddr *) &tcp_server_address,
                sizeof(tcp_server_address));
        if (status == 0)
        {
            /* We can now listen for incoming connections. We only allow a backlog of one
             * connection
             */
            status = listen(tcp_socket, 1);
            if (status != 0)
            {
                printf("Cannot listen on socket: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            /* Cannot bind to socket. */
            printf("Cannot bind to socket: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    /* Allocate Buffer for TCP stream data.
     * (We store it temporarily only since we act as an TCP sink.)
     */
    tcp_buffer = malloc(opt_buffer);
    if (tcp_buffer == NULL)
    {
        puts("Can't allocate buffer for TCP temporary memory.\n");
        exit(EXIT_FAILURE);
    }

    /* Our main loop where we wait for (a) TCP connection(s). */
    puts("Waiting for incoming connections...");
    client_length = sizeof(client_address);

    int tcp_work_socket = accept(tcp_socket, (struct sockaddr *) &client_address,
            (socklen_t *) &client_length);
    printf("Receive connection from %s.\n", inet_ntoa(client_address.sin_addr));
    //char *clientaddress = inet_ntoa(client_address.sin_addr);
    createTraffic(tcp_work_socket, client_address);
    close(tcp_work_socket);
    //printf("Closed connection to %s.\n", inet_ntoa(client_address.sin_addr));
    pthread_join(monitor_thread, NULL);
    printResults();
    sleep(1);
    /* That's a happy ending. */
    exit(EXIT_SUCCESS);
}

void printResults()
{
    printf("\n--------------------Summary--------------------------\n");
    printf("Flow duration: %.1f seconds. Data sent: %.1f Mb. Average Throughput: %.1f Mbps\n",
            flow_duration, data_sent, avg_tp);
    if (actual_time != 0)
    {
        printf("\n--------------------Bursty Information--------------------------\n");
        burst_tp = data_sent / actual_time;
        printf("Burst duration: %.1f seconds. Burst interval: %.1f seconds.\n", on_time, off_time);
        printf("Transmit duration: %.1f seconds. Burst number: %u. Burst Throughput: %.1f Mbps\n",
                actual_time, burst_number, burst_tp);
    }
}

char* trim(char *str)
{
    char *pos;
    while ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
    while ((pos = strchr(str, '\r')) != NULL)
        *pos = '\0';
    return str;
}

void keepsending(int sock, struct sockaddr_in client_address)
{
    memset(reply_string, 65, REPLY_MAXLENGTH);
    if (send(sock, reply_string, REPLY_MAXLENGTH, 0) == -1)
    {
        printf("Send to client %s fail. Reason: %s \n", inet_ntoa(client_address.sin_addr),
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    size += REPLY_MAXLENGTH; // In Byte!!
}

void createTraffic(int sock, struct sockaddr_in client_address)
{
    int recv_bytes;
    struct timeval burst_start;
    if ((recv_bytes = recv(sock, tcp_buffer, opt_buffer, 0)) > 0)
    {
        /* Fill tcp_info structure with data to get the TCP options and the client's
         * name.
         */
        tcp_info_length = sizeof(tcp_info);
        /* Fill tcp_info structure with data */
        tcp_info_length = sizeof(tcp_info);
        char *message = trim(tcp_buffer);
        if (strcmp(message, "tcp") == 0)
        {
            get_now(&time_start);
            get_now(&time_now);
            get_now(&burst_start);
            pthread_create(&monitor_thread, NULL, monitor_function, (void *) &sock);
            //int i = 0;
            if (!chunkSize)
            {
                while (time_to_seconds(&time_start, &time_now) <= opt_time)
                //while (i < 3)
                {
                    keepsending(sock, client_address);
                    get_now(&time_now);
                    // i++;
                }
            }
            else
            {
                int sendingCount = 0;
                long maxSendingCount = chunkSize * 1000 / REPLY_MAXLENGTH;
                while (time_to_seconds(&time_start, &time_now) <= opt_time)
                {
					while (sendingCount < maxSendingCount) {
						keepsending(sock, client_address);
						sendingCount++;
						usleep(1000);
					}
					burst_number += 1;
					actual_time += time_to_ms(&burst_start, &time_now) / 1000;
					usleep(off_time * 1000000);
					get_now(&burst_start);
					get_now(&time_now);
					sendingCount = 0;
                    //printf("%f, %f\n", time_to_ms(&burst_start, &time_now), on_time * 1000);
                }
            }
        }
        else
        {
            printf("Cannot get socket information: %s\n", strerror(errno));
        }
    }
}
