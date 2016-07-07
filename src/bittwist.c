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

#include <semaphore.h>
#include "bittwist.h"

char *program_name;

int32_t thiszone; /* offset from GMT to local time in seconds */

char ebuf[PCAP_ERRBUF_SIZE]; /* pcap error buffer */

#define NOT_RECEIVED 0
#define RECEIVED 1
#define TIMEOUT_SEC 1

/* options */
int vflag = 0;      /* 1 - print timestamp, 2 - print timestamp and hex data */
int len = 0;        /* packet length to send (-1 = captured, 0 = on wire, or positive value <= 65535) */
double speed = 1;   /* multiplier for timestamp difference between 2 adjacent packets */
int linerate = 0;   /* limit packet throughput at the specified Mbps (0 means no limit) */
int interval = 0;   /* a constant interval in seconds (0 means actual interval will be used instead) */
int max_pkts = 0;   /* send up to the specified number of packets */

pcap_t *pcapdesc = NULL;          	/* pcap descriptor */
int curr_pkt_len; 				/* packet length to send */
u_char *curr_pkt_data = NULL;	/* packet data including the link-layer header */
struct pcap_sf_pkthdr* pkt2Rcv_header = NULL;
struct pcap_sf_pkthdr curr_pkt_header;

int waitForPacket, firstPacket;
sem_t semRdy;
binary_semaphore bsemRx, bsemTx;

/* stats */
static u_int pkts_sent = 0;
static u_int bytes_sent = 0;
static u_int failed = 0;
struct timeval start = {0,0};
struct timeval end = {0,0};

struct timeval cur_ts;
struct timeval prev_ts = {0,0};

/**
 * This function extracts the MAC address (from command line format 
 * and sets the mac_addr struct)
 *
 */
int
extmac(char* new_rmac_ptr, u_char* new_rmac)
{
    if (sscanf (new_rmac_ptr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &new_rmac[0], &new_rmac[1],
                    &new_rmac[2], &new_rmac[3], &new_rmac[4], &new_rmac[5]) != 6)
        return 0;
    return 1;
}

u_short extractSrcMacAddr(u_char *srcmacaddr,
                       struct pcap_sf_pkthdr *header)
{
	
    /*
     * Ethernet header (14 bytes)
     * 1. destination MAC (6 bytes)
     * 2. source MAC (6 bytes)
     * 3. type (2 bytes)
     */
    struct ether_header *eth_hdr;
    u_short ether_type;
    int i;

    /* do nothing if Ethernet header is truncated */
    if (header->caplen < ETHER_HDR_LEN)
        return (0);

    eth_hdr = (struct ether_header *)malloc(ETHER_HDR_LEN);
    if (eth_hdr == NULL)
        error("malloc(): cannot allocate memory for eth_hdr");

    /* copy Ethernet header from pkt_data into eth_hdr */
    memcpy(eth_hdr, curr_pkt_data, ETHER_HDR_LEN);
    memcpy(srcmacaddr, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    
    free(eth_hdr);
                    
    return 1;
}

void binsem_post(binary_semaphore *p)
{
    pthread_mutex_lock(&p->mutex);
    p->v += 1;
	pthread_cond_signal(&p->cvar);
    pthread_mutex_unlock(&p->mutex);
}

void binsem_wait(binary_semaphore *p)
{
    pthread_mutex_lock(&p->mutex);
	while (!p->v)
        pthread_cond_wait(&p->cvar, &p->mutex);
    p->v -=1;
    pthread_mutex_unlock(&p->mutex);
}


void binsem_wait_timeout(binary_semaphore *p)
{
	struct timespec ts;
	int ret;
		
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		error("clock_gettime");
	}
	ts.tv_sec += TIMEOUT_RCVPKT;
	
    pthread_mutex_lock(&p->mutex);
	
	while (!p->v)
		ret = pthread_cond_timedwait(&p->cvar, &p->mutex, &ts);		
    p->v -=1;
    pthread_mutex_unlock(&p->mutex);
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    
    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    
    if(vflag)
		INFO("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
 
	if(waitForPacket)
	{		
		// TODO replace those tests by test on IP checksum

		if(header->len!=curr_pkt_header.len)
			return;
		
		// check it's the packet we are waiting for
		if(memcmp(curr_pkt_data, pkt_data, header->len)==0)
		{
			// convert the timestamp to readable format 
			/*local_tv_sec = header.s.tv_sec;
			ltime=localtime(&local_tv_sec);
			strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
			
			printf("%s,%.6d len:%d\n", timestr, header.ts.tv_usec, header.len);*/
			
			if(vflag) INFO("PACKET RECEIVED\n");

			/* copy timestamp for previous packet sent */
			memcpy(&prev_ts, &cur_ts, sizeof(struct timeval));
			
			waitForPacket=0;
			sem_post(&semRdy);
			// wait for packet reader thread read next packet (server may reply quicker than thread reader to read next packet...)
			binsem_wait_timeout(&bsemRx);
		}
	}
}

void* threadTx(void *arg)
{
	struct timeval ts;
	
	while(1)
	{
		binsem_wait(&bsemTx);
		
		/* finish the injection and verbose output before we give way to SIGINT */
		if (pcap_sendpacket(pcapdesc, curr_pkt_data, curr_pkt_len) == -1) {
			notice("%s", pcap_geterr(pcapdesc));
			++failed;
		}
		else {
			++pkts_sent;
			bytes_sent += curr_pkt_len;

			/* copy timestamp for previous packet sent */
			memcpy(&prev_ts, &cur_ts, sizeof(struct timeval));

			/* verbose output */
			if (vflag) {
				if (gettimeofday(&ts, NULL) == -1)
					notice("gettimeofday(): %s", strerror(errno));
				else
					ts_print(&ts);

				INFO("#%d (%d bytes)", pkts_sent, curr_pkt_len);

				if (vflag > 1)
					hex_print(curr_pkt_data, curr_pkt_len);
				else
					INFO("\n");
			}
		}
		sem_post(&semRdy);
	}
	
    return NULL;
}

int send_packets(char *device, char *trace_file, int servermode, u_char *srcmacaddr)
{
    int ret, i, semRxVal, success=TRUE, isTXpacket=FALSE;
    struct pcap_timeval p_ts;
    struct timeval sleep = {0,0};
    struct timespec nsleep;
    u_char pcktsrcmacaddr[ETHER_ADDR_LEN];
	struct timespec ts;
	
	FILE *fp; // file pointer to trace file 
    struct pcap_file_header preamble;    

    notice("trace file: %s", trace_file);
    if ((fp = fopen(trace_file, "rb")) == NULL)
        error("fopen(): error reading %s", trace_file);

    /* preamble occupies the first 24 bytes of a trace file */
    if (fread(&preamble, sizeof(preamble), 1, fp) == 0)
        error("fread(): error reading %s", trace_file);
    if (preamble.magic != PCAP_MAGIC)
        error("%s is not a valid pcap based trace file %x %x", trace_file, preamble.magic, PCAP_MAGIC);    
	
	prev_ts.tv_usec=0;
	prev_ts.tv_sec=0;
	
	while ((ret = fread(&curr_pkt_header, sizeof(curr_pkt_header), 1, fp))) 
	{
		if (ret == 0)
			error("fread(): error reading %s", trace_file);

		/* copy timestamp for current packet */
        memcpy(&p_ts, &curr_pkt_header.ts, sizeof(p_ts));
		cur_ts.tv_sec = p_ts.tv_sec;
		cur_ts.tv_usec = p_ts.tv_usec;

        if (len < 0)        /* captured length */
            curr_pkt_len = curr_pkt_header.caplen;
        else if (len == 0)  /* actual length */
            curr_pkt_len = curr_pkt_header.len;
        else                /* user specified length */
            curr_pkt_len = len;
		
		ret = fread(curr_pkt_data, 1, curr_pkt_len, fp);
		if(ret!=curr_pkt_len)
		{
			for (i = ret; i < curr_pkt_len; i++)
                /* pad trailing bytes with zeros */
                curr_pkt_data[i] = PKT_PAD;
		}

        /*for (i = 0; i < curr_pkt_len; i++) {
            // copy captured packet data starting from link-layer header 
            if (i < curr_pkt_header.caplen) {
                if ((ret = fgetc(fp)) == EOF)
                    error("fgetc(): error reading %s", trace_file);
                curr_pkt_data[i] = ret;
            }
            else
                // pad trailing bytes with zeros 
                curr_pkt_data[i] = PKT_PAD;
        }*/
				
		if(!extractSrcMacAddr(pcktsrcmacaddr, &curr_pkt_header))
			continue;

		if((memcmp(srcmacaddr, pcktsrcmacaddr, ETHER_ADDR_LEN)==0 && servermode==0) ||
			(memcmp(srcmacaddr, pcktsrcmacaddr, ETHER_ADDR_LEN)!=0 && servermode==1) )
			isTXpacket = TRUE;
		else isTXpacket = FALSE;
        		
#if 1
		// only sleep for TX packets
		if(isTXpacket)
		{		
			if (timerisset(&prev_ts)) { /* pass first packet */
				if (speed != 0) {
					if (interval > 0) {
						/* user specified interval is in seconds only */
						sleep.tv_sec = interval;
						if (speed != 1)
							timer_div(&sleep, speed); /* speed factor */
					}
					else {
						/* grab captured interval */
						timersub(&cur_ts, &prev_ts, &sleep);

						if (speed != 1) {
							if (sleep.tv_sec > SLEEP_MAX) /* to avoid integer overflow in timer_div() */
								notice("ignoring speed due to large interval");
							else
								timer_div(&sleep, speed);
						}
					}

					if (linerate > 0) {
						i = linerate_interval(curr_pkt_len);
						/* check if we exceed line rate */
						if ((sleep.tv_sec == 0) && (sleep.tv_usec < i))
							sleep.tv_usec = i; /* exceeded -> adjust */
					}
				}
				else { /* send immediately */
					if (linerate > 0)
						sleep.tv_usec = linerate_interval(curr_pkt_len);
				}

				if (timerisset(&sleep)) {
					//notice("sleep %d seconds %d microseconds", sleep.tv_sec, sleep.tv_usec);
					TIMEVAL_TO_TIMESPEC(&sleep, &nsleep);
					if (nanosleep(&nsleep, NULL) == -1) /* create the artificial slack time */
						notice("nanosleep(): %s", strerror(errno));
				}
			}
		}
#endif  
        /* move file pointer to the end of this packet data */
        if (i < curr_pkt_header.caplen) {
            if (fseek(fp, curr_pkt_header.caplen - curr_pkt_len, SEEK_CUR) != 0)
                error("fseek(): error reading %s", trace_file);
        }

		if(srcmacaddr!=NULL)
		{
			// in servermode, do not send packets having source adress mac == srcmacaddrstr
			// this should be send by the client => wait to receive it
			if(isTXpacket)
			{		
				binsem_post(&bsemTx);
				
				// wait for the packet to be sent
				sem_wait(&semRdy);
			}
			else
			{
				// wait for packet reception
				waitForPacket=1;
				// unlock Rx thread (may be locked waiting reader thread to read next packet)
				if(firstPacket==1) firstPacket=0;
				else binsem_post(&bsemRx);

				// the thread may be waiting for a packet response, but the other side may not have received it
				if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
					error("clock_gettime");
				}
				ts.tv_sec += TIMEOUT_RCVPKT;    
				while ((ret = sem_timedwait(&semRdy, &ts)) == -1 && errno == EINTR)
					continue;       /* Restart if interrupted by handler */
					
				// Check what happened
				if (ret == -1) {
					if (errno == ETIMEDOUT)
						INFO("sem_timedwait() timed out\n");
					else
						error("sem_timedwait");
					
					success=FALSE;
					break;
				} 			
			}
		}
		else
		{
			// classic pcap player mode
			binsem_post(&bsemTx);
			// wait for the packet to be sent
			sem_wait(&semRdy);
		}
	}
	
	(void)fclose(fp);
	return success;
}

void* packetReaderThread(void *arg)
{
	int i, incr=0, loop=1;
	packetReaderArgs *args=(packetReaderArgs*)arg;
		
    if (args->loop > 0) 
	{
		incr=-1;
		loop=args->loop;
	}

	while (loop) {
		for (i = optind; i < args->argc; i++) 
		{
			int retry=0;
			
			while(retry++<MAX_NB_SEND_RETRY)
			{
				waitForPacket=0;
				firstPacket=1;
				
				bsemRx.v=0;
				bsemTx.v=0;
				
				
				if(!send_packets(args->device, args->argv[i], args->servermode, args->srcmacaddr)) 
				{
					INFO("send_packets failed, retry\n");
					if(retry==MAX_NB_SEND_RETRY) error("send_packets max retry reached\n");
				}
				else 
				{
					INFO("send_packets succeed !!\n");
					break;
				}
			}
			
		}
		
		// unlock Rx Thread (last packet from file processed, but it may be waiting from reader thread to read one)
		binsem_post(&bsemRx);
		loop+=incr;
	}	
	
	pcap_breakloop(pcapdesc);
	pcap_close(pcapdesc);
	return NULL;
}

int main(int argc, char **argv)
{
    char *cp;
    int c, err;
    pcap_if_t *devptr;
    int i;
    int devnum;
    char *device = NULL;
    int loop = 1;
    thiszone = gmt2local(0);
    pcap_if_t *alldevs, *d;
	packetReaderArgs pktReaderArgs;
	char *trace_file, srcmacaddr[ETHER_ADDR_LEN];
	int servermode=0;
	
    pthread_t threadTxId, packetReaderThreadId;
	
	pktReaderArgs.srcmacaddr = NULL;	
    if ((cp = strrchr(argv[0], '/')) != NULL)
        program_name = cp + 1;
    else
        program_name = argv[0];

    /* process options */
    while ((c = getopt(argc, argv, "dvxi:s:l:c:m:r:p:w:h")) != -1) {
        switch (c) {
            case 'd':
                if (pcap_findalldevs(&devptr, ebuf) < 0)
                    error("%s", ebuf);
                else {
                    for (i = 0; devptr != 0; i++) {
                        INFO("%d. %s", i + 1, devptr->name);
                        if (devptr->description != NULL)
                            INFO(" (%s)", devptr->description);
                        (void)putchar('\n');
                        devptr = devptr->next;
                    }
                }
                exit(EXIT_SUCCESS);
            case 'v':
                ++vflag;
                break;
            case 'i':
                if ((devnum = atoi(optarg)) != 0) {
                    if (devnum < 0)
                        error("invalid adapter index");
                    if (pcap_findalldevs(&devptr, ebuf) < 0)
                        error("%s", ebuf);
                    else {
                        for (i = 0; i < devnum - 1; i++) {
                            devptr = devptr->next;
                            if (devptr == NULL)
                                error("invalid adapter index");
                        }
                    }
                    device = devptr->name;
                } else {
                    device = optarg;
                }
                break;
            case 's':
                len = strtol(optarg, NULL, 0);
                if (len != -1 && len != 0) {
                    if (len < ETHER_HDR_LEN || len > ETHER_MAX_LEN)
                        error("value for length must be between %d to %d", ETHER_HDR_LEN, ETHER_MAX_LEN);
                }
                break;
            case 'l':
                loop = strtol(optarg, NULL, 0); /* loop infinitely of loop <= 0 */
                break;
            case 'c':
                max_pkts = strtol(optarg, NULL, 0); /* send all packets if max_pkts <= 0 */
                break;
            case 'm':
                speed = strtod(optarg, NULL);
                if (speed > 0 && speed < SPEED_MIN)
                    error("positive value for speed must be at least %f", SPEED_MIN);
                break;
            case 'r':
                linerate = strtol(optarg, NULL, 0);
                if (linerate < LINERATE_MIN || linerate > LINERATE_MAX)
                    error("value for rate must be between %d to %d", LINERATE_MIN, LINERATE_MAX);
                break;
            case 'p':
                interval = strtol(optarg, NULL, 0);
                if (interval < 1 || interval > SLEEP_MAX)
                    error("value for sleep must be between 1 to %d", SLEEP_MAX);
                break;
            case 'w':
				/* These function setup the MAC & IP addresses in the mac_addr & in_addr structs */
				pktReaderArgs.srcmacaddr = srcmacaddr;
				if (extmac(optarg, pktReaderArgs.srcmacaddr) == 0)
					errx(-1, "incorrect source mac %s\n", optarg);
                break;
            case 'x':
				servermode=1;
                break;
            case 'h':
            default:
                usage();
        }
    }

    if (argv[optind] == NULL)
        error("trace file not specified");

    notice("sending packets through %s", device);

    /* buffer to store data for each packet including its link-layer header, freed in cleanup() */
    curr_pkt_data = (u_char *)malloc(sizeof(u_char) * ETHER_MAX_LEN);
    if (curr_pkt_data == NULL)
        error("malloc(): cannot allocate memory for curr_pkt_data");
    memset(curr_pkt_data, 0, ETHER_MAX_LEN);

    /* empty error buffer to grab warning message (if exist) from pcap_open_live() below */
    *ebuf = '\0';
	
    /* note that we are doing this for sending packets, not capture */
    pcapdesc = pcap_open_live(device,
                        ETHER_MAX_LEN,  /* portion of packet to capture */
                        1,              /* promiscuous mode is on */
                        10,             /* read timeout, in milliseconds */
                        ebuf);
    
    if (pcapdesc == NULL)
        error("%s", ebuf);
    else if (*ebuf)
        notice("%s", ebuf); /* warning message from pcap_open_live() above */


	sem_init(&semRdy, 1, 0); 
		
	bsemRx.v=0;
	bsemTx.v=0;
	if (pthread_mutex_init(&bsemRx.mutex, NULL) != 0 || pthread_cond_init(&bsemRx.cvar, NULL) != 0)
	{
		error("\n mutex init failed\n");
		return;
	}	
	if (pthread_mutex_init(&bsemTx.mutex, NULL) != 0 || pthread_cond_init(&bsemTx.cvar, NULL) != 0)
	{
		error("\n mutex init failed\n");
		return;
	}	
			
	err = pthread_create(&threadTxId, NULL, &threadTx, NULL);
	if (err != 0)
		error("\ncan't create thread :[%s]", strerror(err));
	else
		INFO("\n Thread created successfully\n");

	pktReaderArgs.optind=optind;
	pktReaderArgs.argc=argc;
	pktReaderArgs.argv=argv;
	pktReaderArgs.device=device;
	pktReaderArgs.loop=loop;
	pktReaderArgs.servermode=servermode;

	err = pthread_create(&packetReaderThreadId, NULL, &packetReaderThread, &pktReaderArgs);
	if (err != 0)
		error("\ncan't create thread :[%s]", strerror(err));
	else
		INFO("\n Thread created successfully\n");
    	
    /*if(srcipaddrstr)
    {
	// Retrieve the device list 
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, ebuf) == -1)
	{
		error(stderr,"Error in pcap_findalldevs: %s\n", ebuf);
	}

	// Jump to the selected adapter 
	for(d=alldevs, i=0; i< device-1 ;d=d->next, i++);    

	if(d->addresses != NULL)
	{
		// Retrieve the address of the interface 
		netmask=((struct sockaddr_in *)(d->addresses->addr))->sin_addr.S_un.S_addr;    
		//char *ip = inet_ntoa(their_addr.sin_addr)
	}
    }*/

    /* set signal handler for SIGINT (Control-C) */
    (void)signal(SIGINT, cleanup);

    if (gettimeofday(&start, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));
    
    /* start the capture */
    pcap_loop(pcapdesc, 0, packet_handler, NULL);    

    cleanup(0);

    /* NOTREACHED */
    exit(EXIT_SUCCESS);
}

/*
 * Calculate line rate interval in microseconds for the given
 * pkt_len (bytes) and linerate (Mbps)
 *
 * to send packets at line rate with assumption of link speed at X:
 * interval = ((packet length * bits per byte) / (X to bits)) * 1000000
 * +---------------------------------------------------+
 * |            | 10Mbps      | 100Mbps    | 1000Mbps  |
 * +---------------------------------------------------+
 * |   14 bytes | 11 usecs.   | 1 usecs.   | 0 usecs.  |
 * | 1514 bytes | 1155 usecs. | 116 usecs. | 12 usecs. |
 * +---------------------------------------------------+
 */
int linerate_interval(int pkt_len)
{
    return ROUND(((float)pkt_len * 8) / (linerate * 1024 * 1024) * 1000000);
}

void info(void)
{
    struct timeval elapsed;
    float seconds;

    if (gettimeofday(&end, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));
    timersub(&end, &start, &elapsed);
    seconds = elapsed.tv_sec + (float)elapsed.tv_usec / 1000000;

    (void)putchar('\n');
    notice("%u packets (%u bytes) sent", pkts_sent, bytes_sent);
    if (failed)
        notice("%u write attempts failed", failed);
    notice("Elapsed time = %f seconds", seconds);
}

void cleanup(int signum)
{
    free(curr_pkt_data); 
	curr_pkt_data = NULL;
    if (signum == -1)
        exit(EXIT_FAILURE);
    else
        info();
    exit(EXIT_SUCCESS);
}

void timer_div(struct timeval *tvp, double speed)
{
    double interval;

    interval = (tvp->tv_sec * 1000000 + tvp->tv_usec) / speed;
    tvp->tv_sec = interval / 1000000;
    tvp->tv_usec = ROUND(interval) - ((double)tvp->tv_sec * 1000000);
}

/*
 * Reference: tcpdump's gmt2local.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
int32_t gmt2local(time_t t)
{
    register int dt, dir;
    register struct tm *gmt, *loc;
    struct tm sgmt;

    if (t == 0)
        t = time(NULL);
    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);
    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
            (loc->tm_min - gmt->tm_min) * 60;

    /*
     * If the year or julian day is different, we span 00:00 GMT
     * and must add or subtract a day. Check the year first to
     * avoid problems when the julian day wraps.
     */
    dir = loc->tm_year - gmt->tm_year;
    if (dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;
    dt += dir * 24 * 60 * 60;

    return (dt);
}

/*
 * Reference: tcpdump's print-ascii.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void hex_print(register const u_char *cp, register u_int length)
{
    register u_int i, s;
    register int nshorts;
    register u_int oset = 0;

    nshorts = (u_int)length / sizeof(u_short);
    i = 0;
    while (--nshorts >= 0) {
        if ((i++ % 8) == 0) {
            (void)printf("\n\t0x%04x: ", oset);
            oset += 16;
        }
        s = *cp++;
        (void)printf(" %02x%02x", s, *cp++);
    }
    if (length & 1) {
        if ((i % 8) == 0)
            (void)printf("\n\t0x%04x: ", oset);
        (void)printf(" %02x", *cp);
    }
    (void)putchar('\n');
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void ts_print(register const struct timeval *tvp)
{
    register int s;

    s = (tvp->tv_sec + thiszone) % 86400;
    (void)printf("%02d:%02d:%02d.%06u ",
            s / 3600, (s % 3600) / 60, s % 60, (unsigned)tvp->tv_usec);
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void notice(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void error(const char *fmt, ...)
{
    va_list ap;
    (void)fprintf(stderr, "%s: ", program_name);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
    cleanup(-1);
}

void usage(void)
{
    (void)fprintf(stderr, "%s version %s\n"
        "%s\n"
        "Usage: %s [-d] [-v] [-i interface] [-s length] [-l loop] [-c count]\n"
        "                [-m speed] [-r rate] [-p sleep] [-h] pcap-file(s)\n"
        "\nOptions:\n"
        " -d             Print a list of network interfaces available.\n"
        " -v             Print timestamp for each packet.\n"
        " -vv            Print timestamp and hex data for each packet.\n"
        " -i interface   Send 'pcap-file(s)' out onto the network through 'interface'.\n"
        " -s length      Packet length to send. Set 'length' to:\n"
        "                     0 to send the actual packet length. This is the default.\n"
        "                    -1 to send the captured length.\n"
        "                or any other value from %d to %d.\n"
        " -l loop        Send 'pcap-file(s)' out onto the network for 'loop' times.\n"
        "                Set 'loop' to 0 to send 'pcap-file(s)' until stopped.\n"
        "                To stop, type Control-C.\n"
        " -c count       Send up to 'count' packets.\n"
        "                Default is to send all packets from 'pcap-file(s)'.\n"
        " -m speed       Set interval multiplier to 'speed'.\n"
        "                Set 'speed' to 0 or less to send the next packet immediately.\n"
        "                Minimum positive value for 'speed' is %f.\n"
        " -r rate        Limit the sending to 'rate' Mbps.\n"
        "                Value for 'rate' must be between %d to %d.\n"
        "                This option is meant to limit the maximum packet throughput.\n"
        "                If you want to send packets at line rate of 100Mbps,\n"
        "                try -m 0 -r 100\n"
        " -p sleep       Set interval to 'sleep' (in seconds), ignoring the actual\n"
        "                interval.\n"
        "                Value for 'sleep' must be between 1 to %d.\n"
        " -w macaddr     only sends packets from this source.\n"
        " -x             Set server mode.\n"
        " -h             Print version information and usage.\n",
        program_name, BITTWIST_VERSION, pcap_lib_version(), program_name, ETHER_HDR_LEN,
        ETHER_MAX_LEN, SPEED_MIN, LINERATE_MIN, LINERATE_MAX, SLEEP_MAX);
    exit(EXIT_SUCCESS);
}
