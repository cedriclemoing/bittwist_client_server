/*
 * bittwist - pcap based ethernet packet generator
 * Copyright (C) 2006 - 2012 Addy Yeow Chin Heng <ayeowch@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef _BITTWIST_H_
#define _BITTWIST_H_

#include "def.h"

int send_packets(char *device, char *trace_file, int servermode, u_char *srcmacaddr);
int linerate_interval(int pkt_len);
void info(void);
void cleanup(int signum);
void timer_div(struct timeval *tvp, double speed);
int32_t gmt2local(time_t t);
void hex_print(register const u_char *cp, register u_int length);
void ts_print(register const struct timeval *tvp);
void notice(const char *fmt, ...);
void error(const char *fmt, ...);
void usage(void);

// set timeout to restart packet sending from the begining
#define TIMEOUT_RCVPKT 10
// number of retries per input pcap file (retry occurs upon a packet loss, or server-client synchronization problem)
#define MAX_NB_SEND_RETRY 10

// 6 byte MAC Address
struct mac_addr { 
    unsigned char byte1; 
    unsigned char byte2; 
    unsigned char byte3; 
    unsigned char byte4; 
    unsigned char byte5; 
    unsigned char byte6; 
};
	
typedef struct {
	int optind;
    int argc;
    char **argv;
	char *device;
	int loop;
	int servermode;
	u_char *srcmacaddr;
} packetReaderArgs;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cvar;
    int v;
} binary_semaphore;

#endif  /* !_BITTWIST_H_ */
