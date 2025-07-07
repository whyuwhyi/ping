#include <arpa/inet.h> /* inet(3) functions */
#include <errno.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <getopt.h>
#include <netinet/icmp6.h>
#include <netinet/in.h> /* sockaddr_in{} and other Internet defns */
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h> /* basic socket definitions */
#include <sys/time.h>   /* timeval{} for select() */
#include <sys/types.h>  /* basic system data types */
#include <sys/un.h>     /* for Unix domain sockets */
#include <syslog.h>
#include <time.h> /* timespec{} for pselect() */
#include <unistd.h>
#ifdef HAVE_SOCKADDR_DL_STRUCT
#include <net/if_dl.h>
#endif

#define IPV6

#define BUFSIZE 1500
#define MAXLINE 4096
#define PING_VERSION "1.0.0"

/* IP options constants if not defined */
#ifndef IPOPT_TIMESTAMP
#define IPOPT_TIMESTAMP 68
#endif

#ifndef IP_PMTUDISC_DO
#define IP_PMTUDISC_DO 2
#endif
#ifndef IP_PMTUDISC_DONT
#define IP_PMTUDISC_DONT 0
#endif
#ifndef IP_PMTUDISC_WANT
#define IP_PMTUDISC_WANT 1
#endif
#ifndef IP_PMTUDISC_PROBE
#define IP_PMTUDISC_PROBE 3
#endif

/* globals */
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int datalen; /* #bytes of data, following ICMP header */
char *host;
int nsent; /* add 1 for each sendto() */
pid_t pid; /* our PID */
int sockfd;
int verbose;
int daemon_proc; /* set nonzero by daemon_init() */

/* original ping1 options */
int    count;         /* -c: number of packets to send */
double interval;      /* -i: interval between packets (seconds) */
int    quiet;         /* -q: quiet output */
int    ttl;           /* -t: time to live */
double timeout;       /* -W: timeout for each reply (seconds) */
int    broadcast;     /* -b: allow broadcast */
int	nrecv;	      /* the sign of droping other icmp packet */
int	preceived;    /* packet loss */

/* ping2 extensions */
int debug_mode;       /* -d: enable SO_DEBUG */
int force_ipv4;       /* -4: force IPv4 */
int force_ipv6;       /* -6: force IPv6 */
int mark_value;       /* -m: packet mark value */
char *pmtu_discovery; /* -M: Path MTU Discovery mode */
char *interface;      /* -I: network interface */
char *timestamp_opt;  /* -T: timestamp option */
int flood_mode;       /* -f: flood ping mode */
int numeric_mode;     /* -n: numeric output mode */
char *pattern;        /* -p: fill pattern */
int bypass_route;     /* -r: bypass routing table */
int record_route;     /* -R: record route */
int preload_count;    /* -l: preload mode */
int deadline;         /* -w: deadline in seconds */
time_t start_time;    /* start time for deadline calculation */

/* additional new options */
int rtt_precision;    /* -3: RTT precision mode */
int print_timestamps; /* -D: print timestamps */
int sndbuf_size;      /* -S: SO_SNDBUF socket option value */
int user_latency;     /* -U: print user-to-user latency */

/* RTT statistics */
double rtt_min;       /* minimum RTT */
double rtt_max;       /* maximum RTT */
double rtt_sum;       /* sum of RTTs for average */
double rtt_sum_sq;    /* sum of squares for mdev calculation */
int rtt_count;        /* count of valid RTTs */

/* function prototypes */
void proc_v4(char *, ssize_t, struct timeval *);
void proc_v6(char *, ssize_t, struct timeval *);
void send_v4(void);
void send_v6(void);
void readloop(void);
void sig_alrm(int);
void tv_sub(struct timeval *, struct timeval *);

char *Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo *host_serv(const char *host, const char *serv, int family,
                           int socktype);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);
void err_quit(const char *fmt, ...);
void err_sys(const char *fmt, ...);
void usage(void);
void print_version(void);
int is_broadcast_ip(const struct sockaddr_in *addr);
unsigned short in_cksum(unsigned short *addr, int len);
void print_timestamp(void);

struct proto {
  void (*fproc)(char *, ssize_t, struct timeval *);
  void (*fsend)(void);
  struct sockaddr *sasend; /* sockaddr{} for send, from getaddrinfo */
  struct sockaddr *sarecv; /* sockaddr{} for receiving */
  socklen_t salen;         /* length of sockaddr{}s */
  int icmpproto;           /* IPPROTO_xxx value for ICMP */
} *pr;
