#include "ping.h"

struct proto proto_v4 = {proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};

#ifdef IPV6
struct proto proto_v6 = {proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6};
#endif

int datalen = 56; /* data that goes with ICMP echo request */

int main(int argc, char **argv) {
  int c;
  struct addrinfo *ai;

  opterr = 0; /* don't want getopt() writing to stderr */
  while ((c = getopt(argc, argv, "v46dm:M:I:T:")) != -1) {
    switch (c) {
    case 'v':
      verbose++;
      break;
    
    case '4':
      force_ipv4 = 1;
      break;
      
    case '6':
      force_ipv6 = 1;
      break;
      
    case 'd':
      debug_mode = 1;
      break;
      
    case 'm':
      mark_value = atoi(optarg);
      break;
      
    case 'M':
      pmtu_discovery = optarg;
      break;
      
    case 'I':
      interface = optarg;
      break;
      
    case 'T':
      timestamp_opt = optarg;
      break;

    case '?':
      err_quit("unrecognized option: %c", c);
    }
  }

  if (optind != argc - 1)
    err_quit("usage: ping [ -v46d ] [ -m mark ] [ -M pmtudisc ] [ -I interface ] [ -T tstamp ] <hostname>");
  host = argv[optind];

  /* validate conflicting options */
  if (force_ipv4 && force_ipv6)
    err_quit("cannot specify both -4 and -6");
    
  /* validate PMTUdisc option */
  if (pmtu_discovery && 
      strcmp(pmtu_discovery, "do") != 0 &&
      strcmp(pmtu_discovery, "dont") != 0 &&
      strcmp(pmtu_discovery, "want") != 0 &&
      strcmp(pmtu_discovery, "probe") != 0)
    err_quit("invalid PMTUdisc option: %s (use do/dont/want/probe)", pmtu_discovery);
    
  /* validate timestamp option */
  if (timestamp_opt &&
      strcmp(timestamp_opt, "tsonly") != 0 &&
      strcmp(timestamp_opt, "tsandaddr") != 0 &&
      strcmp(timestamp_opt, "tsprespec") != 0)
    err_quit("invalid timestamp option: %s (use tsonly/tsandaddr/tsprespec)", timestamp_opt);

  pid = getpid();
  signal(SIGALRM, sig_alrm);

  /* determine address family based on options */
  int family = AF_UNSPEC;
  if (force_ipv4)
    family = AF_INET;
  else if (force_ipv6)
    family = AF_INET6;
    
  ai = host_serv(host, NULL, family, 0);

  printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
         Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

  /* 4initialize according to protocol */
  if (ai->ai_family == AF_INET) {
    pr = &proto_v4;
#ifdef IPV6
  } else if (ai->ai_family == AF_INET6) {
    pr = &proto_v6;
    if (IN6_IS_ADDR_V4MAPPED(
            &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr)))
      err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
  } else
    err_quit("unknown address family %d", ai->ai_family);

  pr->sasend = ai->ai_addr;
  pr->sarecv = calloc(1, ai->ai_addrlen);
  pr->salen = ai->ai_addrlen;

  readloop();

  exit(0);
}

void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv) {
  int hlen1, icmplen;
  double rtt;
  struct ip *ip;
  struct icmp *icmp;
  struct timeval *tvsend;

  ip = (struct ip *)ptr;  /* start of IP header */
  hlen1 = ip->ip_hl << 2; /* length of IP header */

  icmp = (struct icmp *)(ptr + hlen1); /* start of ICMP header */
  if ((icmplen = len - hlen1) < 8)
    err_quit("icmplen (%d) < 8", icmplen);

  if (icmp->icmp_type == ICMP_ECHOREPLY) {
    if (icmp->icmp_id != pid)
      return; /* not a response to our ECHO_REQUEST */
    if (icmplen < 16)
      err_quit("icmplen (%d) < 16", icmplen);

    tvsend = (struct timeval *)icmp->icmp_data;
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n", icmplen,
           Sock_ntop_host(pr->sarecv, pr->salen), icmp->icmp_seq, ip->ip_ttl,
           rtt);

  } else if (verbose) {
    printf("  %d bytes from %s: type = %d, code = %d\n", icmplen,
           Sock_ntop_host(pr->sarecv, pr->salen), icmp->icmp_type,
           icmp->icmp_code);
  }
}

void proc_v6(char *ptr, ssize_t len, struct timeval *tvrecv) {
#ifdef IPV6
  int hlen1, icmp6len;
  double rtt;
  struct ip6_hdr *ip6;
  struct icmp6_hdr *icmp6;
  struct timeval *tvsend;

  /*
  ip6 = (struct ip6_hdr *) ptr;		// start of IPv6 header
  hlen1 = sizeof(struct ip6_hdr);
  if (ip6->ip6_nxt != IPPROTO_ICMPV6)
          err_quit("next header not IPPROTO_ICMPV6");

  icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
  if ( (icmp6len = len - hlen1) < 8)
          err_quit("icmp6len (%d) < 8", icmp6len);
  */

  icmp6 = (struct icmp6_hdr *)ptr;
  if ((icmp6len = len) < 8) // len-40
    err_quit("icmp6len (%d) < 8", icmp6len);

  if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
    if (icmp6->icmp6_id != pid)
      return; /* not a response to our ECHO_REQUEST */
    if (icmp6len < 16)
      err_quit("icmp6len (%d) < 16", icmp6len);

    tvsend = (struct timeval *)(icmp6 + 1);
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n", icmp6len,
           Sock_ntop_host(pr->sarecv, pr->salen), icmp6->icmp6_seq,
           ip6->ip6_hlim, rtt);

  } else if (verbose) {
    printf("  %d bytes from %s: type = %d, code = %d\n", icmp6len,
           Sock_ntop_host(pr->sarecv, pr->salen), icmp6->icmp6_type,
           icmp6->icmp6_code);
  }
#endif /* IPV6 */
}

unsigned short in_cksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  /* 4mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }

  /* 4add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return (answer);
}

void send_v4(void) {
  int len;
  struct icmp *icmp;

  icmp = (struct icmp *)sendbuf;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = pid;
  icmp->icmp_seq = nsent++;
  gettimeofday((struct timeval *)icmp->icmp_data, NULL);

  len = 8 + datalen; /* checksum ICMP header and data */
  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = in_cksum((unsigned short *)icmp, len);

  sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

void send_v6() {
#ifdef IPV6
  int len;
  struct icmp6_hdr *icmp6;

  icmp6 = (struct icmp6_hdr *)sendbuf;
  icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
  icmp6->icmp6_code = 0;
  icmp6->icmp6_id = pid;
  icmp6->icmp6_seq = nsent++;
  gettimeofday((struct timeval *)(icmp6 + 1), NULL);

  len = 8 + datalen; /* 8-byte ICMPv6 header */

  sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
  /* kernel calculates and stores checksum for us */
#endif /* IPV6 */
}

void readloop(void) {
  int size;
  char recvbuf[BUFSIZE];
  socklen_t len;
  ssize_t n;
  struct timeval tval;

  sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
  setuid(getuid()); /* don't need special permissions any more */

  size = 60 * 1024; /* OK if setsockopt fails */
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
  
  /* enable debug mode if requested */
  if (debug_mode) {
    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) < 0)
      err_sys("setsockopt SO_DEBUG");
  }
  
  /* set packet mark if specified */
  if (mark_value) {
#ifdef SO_MARK
    if (setsockopt(sockfd, SOL_SOCKET, SO_MARK, &mark_value, sizeof(mark_value)) < 0)
      err_sys("setsockopt SO_MARK");
#else
    err_quit("SO_MARK not supported on this system");
#endif
  }
  
  /* set Path MTU Discovery mode if specified */
  if (pmtu_discovery && pr->sasend->sa_family == AF_INET) {
#ifdef IP_MTU_DISCOVER
    int pmtu_val;
    if (strcmp(pmtu_discovery, "do") == 0)
      pmtu_val = IP_PMTUDISC_DO;
    else if (strcmp(pmtu_discovery, "dont") == 0)
      pmtu_val = IP_PMTUDISC_DONT;
    else if (strcmp(pmtu_discovery, "want") == 0)
      pmtu_val = IP_PMTUDISC_WANT;
    else if (strcmp(pmtu_discovery, "probe") == 0)
      pmtu_val = IP_PMTUDISC_PROBE;
    
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu_val, sizeof(pmtu_val)) < 0)
      err_sys("setsockopt IP_MTU_DISCOVER");
#else
    err_quit("IP_MTU_DISCOVER not supported on this system");
#endif
  }
  
  /* bind to specific interface if specified */
  if (interface) {
    /* try to bind by interface name */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) < 0) {
      /* if binding by name fails, try to parse as IP address */
      struct sockaddr_in addr;
      if (inet_pton(AF_INET, interface, &addr.sin_addr) == 1) {
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
          err_sys("bind to interface %s", interface);
      } else {
        err_sys("bind to interface %s", interface);
      }
    }
  }
  
  /* set timestamp option if specified (IPv4 only) */
  if (timestamp_opt && pr->sasend->sa_family == AF_INET) {
#ifdef IP_OPTIONS
    unsigned char ts_opt[40];
    int ts_len;
    
    memset(ts_opt, 0, sizeof(ts_opt));
    ts_opt[0] = IPOPT_TIMESTAMP; /* timestamp option */
    
    if (strcmp(timestamp_opt, "tsonly") == 0) {
      ts_opt[1] = 36;  /* option length */
      ts_opt[2] = 5;   /* pointer */
      ts_opt[3] = 0;   /* flags: timestamps only */
      ts_len = 36;
    } else if (strcmp(timestamp_opt, "tsandaddr") == 0) {
      ts_opt[1] = 36;  /* option length */
      ts_opt[2] = 5;   /* pointer */
      ts_opt[3] = 1;   /* flags: timestamps and addresses */
      ts_len = 36;
    } else if (strcmp(timestamp_opt, "tsprespec") == 0) {
      ts_opt[1] = 36;  /* option length */
      ts_opt[2] = 5;   /* pointer */
      ts_opt[3] = 3;   /* flags: prespecified addresses */
      ts_len = 36;
    }
    
    if (setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, ts_opt, ts_len) < 0)
      err_sys("setsockopt IP_OPTIONS (timestamp)");
#else
    err_quit("IP timestamp options not supported on this system");
#endif
  }

  sig_alrm(SIGALRM); /* send first packet */

  for (;;) {
    len = pr->salen;
    n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      else
        err_sys("recvfrom error");
    }

    gettimeofday(&tval, NULL);
    (*pr->fproc)(recvbuf, n, &tval);
  }
}

void sig_alrm(int signo) {
  (*pr->fsend)();

  alarm(1);
  return; /* probably interrupts recvfrom() */
}

void tv_sub(struct timeval *out, struct timeval *in) {
  if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen) {
  static char str[128]; /* Unix domain is largest */

  switch (sa->sa_family) {
  case AF_INET: {
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

    if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
      return (NULL);
    return (str);
  }

#ifdef IPV6
  case AF_INET6: {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

    if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
      return (NULL);
    return (str);
  }
#endif

#ifdef HAVE_SOCKADDR_DL_STRUCT
  case AF_LINK: {
    struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

    if (sdl->sdl_nlen > 0)
      snprintf(str, sizeof(str), "%*s", sdl->sdl_nlen, &sdl->sdl_data[0]);
    else
      snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
    return (str);
  }
#endif
  default:
    snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
             sa->sa_family, salen);
    return (str);
  }
  return (NULL);
}

char *Sock_ntop_host(const struct sockaddr *sa, socklen_t salen) {
  char *ptr;

  if ((ptr = sock_ntop_host(sa, salen)) == NULL)
    err_sys("sock_ntop_host error"); /* inet_ntop() sets errno */
  return (ptr);
}

struct addrinfo *host_serv(const char *host, const char *serv, int family,
                           int socktype) {
  int n;
  struct addrinfo hints, *res;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_CANONNAME; /* always return canonical name */
  hints.ai_family = family;      /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
  hints.ai_socktype = socktype;  /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

  if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
    return (NULL);

  return (res); /* return pointer to first on linked list */
}
/* end host_serv */

static void err_doit(int errnoflag, int level, const char *fmt, va_list ap) {
  int errno_save, n;
  char buf[MAXLINE];

  errno_save = errno; /* value caller might want printed */
#ifdef HAVE_VSNPRINTF
  vsnprintf(buf, sizeof(buf), fmt, ap); /* this is safe */
#else
  vsprintf(buf, fmt, ap); /* this is not safe */
#endif
  n = strlen(buf);
  if (errnoflag)
    snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
  strcat(buf, "\n");

  if (daemon_proc) {
    syslog(level, "%s", buf);
    /* syslog(level, buf); */
  } else {
    fflush(stdout); /* in case stdout and stderr are the same */
    fputs(buf, stderr);
    fflush(stderr);
  }
  return;
}

/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void err_quit(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  err_doit(0, LOG_ERR, fmt, ap);
  va_end(ap);
  exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void err_sys(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  err_doit(1, LOG_ERR, fmt, ap);
  va_end(ap);
  exit(1);
}

/*
 * getopt是由Unix标准库提供的函数，查看命令man 3 getopt。
 *
 * getopt函数的参数：
 * 参数argc和argv：通常是从main的参数直接传递而来，argc是参数的数量，
 *                 argv是一个常量字符串数组的地址。
 * 参数optstring：一个包含正确选项字符的字符串，如果一个字符后面有冒号，
                  那么这个选项在传递参数时就需要跟着一个参数。

 * 外部变量：
 * char *optarg：如果有参数，则包含当前选项参数字符串
 * int optind：argv的当前索引值。当getopt函数在while循环中使用时，
 *             剩下的字符串为操作数，下标从optind到argc-1。
 * int opterr：这个变量非零时，getopt()函数为“无效选项”和“缺少参数选项，
 *             并输出其错误信息。
 * int optopt：当发现无效选项字符之时，getopt()函数或返回 \’ ? \’ 字符，
 *             或返回字符 \’ : \’ ，并且optopt包含了所发现的无效选项字符。
 */
