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
  /* Set defaults for ping1 options */
  count = 0;
  interval = 1.0;
  quiet = 0;
  ttl = 0;
  timeout = 1.0;
  broadcast = 0;

  /* Set defaults for new options */
  rtt_precision = 0;
  print_timestamps = 0;
  sndbuf_size = 0;
  user_latency = 0;
  
  /* Initialize RTT statistics */
  rtt_min = 999999.0;
  rtt_max = 0.0;
  rtt_sum = 0.0;
  rtt_sum_sq = 0.0;
  rtt_count = 0;

  while ((c = getopt(argc, argv,
                     "bc:hi:qs:t:vW:46dm:M:I:T:fnp:rRl:w:V3DS:U")) != -1) {
    switch (c) {
    case 'b':
      broadcast = 1;
      break;
    case 'c':
      count = atoi(optarg);
      break;
    case 'h':
      usage();
      exit(0);
    case 'i':
      interval = atof(optarg);
      if (interval <= 0)
        err_quit("interval must be > 0");
      break;
    case 'q':
      quiet = 1;
      break;
    case 's':
      datalen = atoi(optarg);
      if (datalen < 0)
        err_quit("invalid packet size");
      break;
    case 't':
      ttl = atoi(optarg);
      if (ttl < 1 || ttl > 255)
        err_quit("ttl must be 1-255");
      break;
    case 'v':
      verbose++;
      break;
    case 'W':
      timeout = atof(optarg);
      if (timeout <= 0)
        err_quit("timeout must be >= 0");
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
    case 'f':
      flood_mode = 1;
      break;
    case 'n':
      numeric_mode = 1;
      break;
    case 'p':
      pattern = optarg;
      break;
    case 'r':
      bypass_route = 1;
      break;
    case 'R':
      record_route = 1;
      break;
    case 'l':
      preload_count = atoi(optarg);
      break;
    case 'w':
      deadline = atoi(optarg);
      break;
    case 'V':
      print_version();
      exit(0);
    case '3':
      rtt_precision = 1;
      break;
    case 'D':
      print_timestamps = 1;
      break;
    case 'S':
      sndbuf_size = atoi(optarg);
      if (sndbuf_size <= 0)
        err_quit("send buffer size must be > 0");
      break;
    case 'U':
      user_latency = 1;
      break;

    case '?':
      usage();
      exit(1);
    }
  }

  if (optind != argc - 1)
    err_quit("usage: ping [ options ] <hostname>");
  host = argv[optind];

  /* validate conflicting options */
  if (force_ipv4 && force_ipv6)
    err_quit("cannot specify both -4 and -6");

  /* validate PMTUdisc option */
  if (pmtu_discovery && strcmp(pmtu_discovery, "do") != 0 &&
      strcmp(pmtu_discovery, "dont") != 0 &&
      strcmp(pmtu_discovery, "want") != 0 &&
      strcmp(pmtu_discovery, "probe") != 0)
    err_quit("invalid PMTUdisc option: %s (use do/dont/want/probe)",
             pmtu_discovery);

  /* validate timestamp option */
  if (timestamp_opt && strcmp(timestamp_opt, "tsonly") != 0 &&
      strcmp(timestamp_opt, "tsandaddr") != 0 &&
      strcmp(timestamp_opt, "tsprespec") != 0)
    err_quit("invalid timestamp option: %s (use tsonly/tsandaddr/tsprespec)",
             timestamp_opt);

  /* additional ping2 validations */
  if (flood_mode && getuid() != 0)
    err_quit("flood mode requires root privileges");

  if (preload_count > 0 && getuid() != 0)
    err_quit("preload mode requires root privileges");

  if (pattern) {
    int len = strlen(pattern);
    if (len % 2 != 0)
      err_quit("pattern must be an even number of hex digits");
    for (int i = 0; i < len; i++) {
      if (!((pattern[i] >= '0' && pattern[i] <= '9') ||
            (pattern[i] >= 'a' && pattern[i] <= 'f') ||
            (pattern[i] >= 'A' && pattern[i] <= 'F')))
        err_quit("pattern must contain only hex digits");
    }
  }

  if (preload_count < 0)
    err_quit("preload count must be non-negative");

  if (deadline < 0)
    err_quit("deadline must be non-negative");

  pid = getpid();
  signal(SIGALRM, sig_alrm);

  /* determine address family based on options */
  int family = AF_UNSPEC;
  if (force_ipv4)
    family = AF_INET;
  else if (force_ipv6)
    family = AF_INET6;

  /* set deadline alarm if specified */
  if (deadline > 0) {
    signal(SIGALRM, sig_alrm);
    alarm(deadline);
  }

  ai = host_serv(host, NULL, family, 0);
  if (ai == NULL)
    err_quit("host_serv error for %s", host);

  printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
         Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

  /* 4initialize according to protocol */
  if (ai->ai_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
    if (is_broadcast_ip(sin) && !broadcast) {
      err_quit("ping: Do you want to ping broadcast? Then -b. If not, check "
               "your local firewall rules");
    }
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
  char addr_str[INET_ADDRSTRLEN];

  ip = (struct ip *)ptr;  /* start of IP header */
  hlen1 = ip->ip_hl << 2; /* length of IP header */

  icmp = (struct icmp *)(ptr + hlen1); /* start of ICMP header */
  if ((icmplen = len - hlen1) < 8)
    err_quit("icmplen (%d) < 8", icmplen);

  if (icmp->icmp_type == ICMP_ECHOREPLY) {
    if (icmp->icmp_id != (pid & 0xFFFF)) {
      nrecv = 1; /* signing drop packet */
      return;    /* not a response to our ECHO_REQUEST */
    }
    if (icmplen < 16)
      err_quit("icmplen (%d) < 16", icmplen);

    tvsend = (struct timeval *)icmp->icmp_data;
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    /* Update RTT statistics and print response */
    {
      /* Update RTT statistics */
      rtt_count++;
      rtt_sum += rtt;
      rtt_sum_sq += rtt * rtt;
      if (rtt < rtt_min) rtt_min = rtt;
      if (rtt > rtt_max) rtt_max = rtt;
      /* print timestamp if requested */
      if (print_timestamps && !quiet) {
        print_timestamp();
      }

      /* handle numeric mode */
      if (numeric_mode) {
        inet_ntop(AF_INET, &ip->ip_src, addr_str, INET_ADDRSTRLEN);
        if (!quiet) {
          if (user_latency) {
            if (rtt_precision) {
              printf("%d bytes from %s: seq=%u, ttl=%d, time=%.6f ms\n",
                     icmplen, addr_str, icmp->icmp_seq, ip->ip_ttl, rtt);
            } else {
              printf("%d bytes from %s: seq=%u, ttl=%d, time=%.3f ms\n",
                     icmplen, addr_str, icmp->icmp_seq, ip->ip_ttl, rtt);
            }
          } else {
            if (rtt_precision) {
              printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.6f ms\n", icmplen,
                     addr_str, icmp->icmp_seq, ip->ip_ttl, rtt);
            } else {
              printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n", icmplen,
                     addr_str, icmp->icmp_seq, ip->ip_ttl, rtt);
            }
          }
        }
      } else {
        /* try to resolve hostname from IP */
        struct hostent *hent;
        struct in_addr addr;
        addr.s_addr = ip->ip_src.s_addr;
        hent = gethostbyaddr(&addr, sizeof(addr), AF_INET);
        if (hent != NULL) {
          if (!quiet) {
            if (user_latency) {
              if (rtt_precision) {
                printf("%d bytes from %s (%s): seq=%u, ttl=%d, time=%.6f ms\n",
                       icmplen, hent->h_name, inet_ntoa(addr), icmp->icmp_seq,
                       ip->ip_ttl, rtt);
              } else {
                printf("%d bytes from %s (%s): seq=%u, ttl=%d, time=%.3f ms\n",
                       icmplen, hent->h_name, inet_ntoa(addr), icmp->icmp_seq,
                       ip->ip_ttl, rtt);
              }
            } else {
              if (rtt_precision) {
                printf("%d bytes from %s (%s): seq=%u, ttl=%d, rtt=%.6f ms\n",
                       icmplen, hent->h_name, inet_ntoa(addr), icmp->icmp_seq,
                       ip->ip_ttl, rtt);
              } else {
                printf("%d bytes from %s (%s): seq=%u, ttl=%d, rtt=%.3f ms\n",
                       icmplen, hent->h_name, inet_ntoa(addr), icmp->icmp_seq,
                       ip->ip_ttl, rtt);
              }
            }
          }
        } else {
          if (!quiet) {
            if (user_latency) {
              if (rtt_precision) {
                printf("%d bytes from %s: seq=%u, ttl=%d, time=%.6f ms\n",
                       icmplen, inet_ntoa(addr), icmp->icmp_seq, ip->ip_ttl,
                       rtt);
              } else {
                printf("%d bytes from %s: seq=%u, ttl=%d, time=%.3f ms\n",
                       icmplen, inet_ntoa(addr), icmp->icmp_seq, ip->ip_ttl,
                       rtt);
              }
            } else {
              if (rtt_precision) {
                printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.6f ms\n",
                       icmplen, inet_ntoa(addr), icmp->icmp_seq, ip->ip_ttl,
                       rtt);
              } else {
                printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                       icmplen, inet_ntoa(addr), icmp->icmp_seq, ip->ip_ttl,
                       rtt);
              }
            }
          }
        }
      }

      /* display route record if enabled */
      if (record_route) {
        unsigned char *cp = (unsigned char *)ip + sizeof(struct ip);
        unsigned char *end = (unsigned char *)ip + (ip->ip_hl << 2);

        while (cp < end) {
          if (*cp == IPOPT_RR && cp + 1 < end) {
            int opt_len = *(cp + 1);
            if (opt_len >= 3 && cp + opt_len <= end) {
              int ptr = *(cp + 2);
              if (ptr > 3) { /* Only show if there are recorded addresses */
                printf("RR:");

                for (int i = 3; i < ptr - 1 && i + 3 < opt_len; i += 4) {
                  if (cp + i + 3 < end) {
                    struct in_addr addr;
                    memcpy(&addr, cp + i, 4);
                    if (addr.s_addr != 0) {
                      printf(" %s", inet_ntoa(addr));
                    }
                  }
                }
                printf("\n");
              }
            }
            break;
          }
          if (*cp == IPOPT_EOL)
            break;
          if (*cp == IPOPT_NOP) {
            cp++;
            continue;
          }
          if (cp + 1 >= end)
            break;
          int next_len = *(cp + 1);
          if (next_len < 2)
            break;
          cp += next_len;
        }
      }
    }

  } else if (verbose) {
    if (numeric_mode) {
      inet_ntop(AF_INET, &ip->ip_src, addr_str, INET_ADDRSTRLEN);
      printf("  %d bytes from %s: type = %d, code = %d\n", icmplen, addr_str,
             icmp->icmp_type, icmp->icmp_code);
    } else {
      printf("  %d bytes from %s: type = %d, code = %d\n", icmplen,
             Sock_ntop_host(pr->sarecv, pr->salen), icmp->icmp_type,
             icmp->icmp_code);
    }
  } else {
    nrecv = 1; /* signing drop packet */
  }
}

void proc_v6(char *ptr, ssize_t len, struct timeval *tvrecv) {
#ifdef IPV6
  int hlen1, icmp6len;
  double rtt;
  struct ip6_hdr *ip6;
  struct icmp6_hdr *icmp6;
  struct timeval *tvsend;
  char addr_str[INET6_ADDRSTRLEN];

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
    if (icmp6->icmp6_id != (pid & 0xFFFF)) {
      nrecv = 1; /* signing drop packet */
      return;    /* not a response to our ECHO_REQUEST */
    }
    if (icmp6len < 16)
      err_quit("icmp6len (%d) < 16", icmp6len);

    tvsend = (struct timeval *)(icmp6 + 1);
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    /* Update RTT statistics and print response */
    {
      /* Update RTT statistics */
      rtt_count++;
      rtt_sum += rtt;
      rtt_sum_sq += rtt * rtt;
      if (rtt < rtt_min) rtt_min = rtt;
      if (rtt > rtt_max) rtt_max = rtt;
      /* print timestamp if requested */
      if (print_timestamps && !quiet) {
        print_timestamp();
      }

      /* handle numeric mode */
      if (numeric_mode) {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)pr->sarecv)->sin6_addr,
                  addr_str, INET6_ADDRSTRLEN);
        if (!quiet) {
          if (user_latency) {
            if (rtt_precision) {
              printf("%d bytes from %s: seq=%u, time=%.6f ms\n", icmp6len,
                     addr_str, icmp6->icmp6_seq, rtt);
            } else {
              printf("%d bytes from %s: seq=%u, time=%.3f ms\n", icmp6len,
                     addr_str, icmp6->icmp6_seq, rtt);
            }
          } else {
            if (rtt_precision) {
              printf("%d bytes from %s: seq=%u, rtt=%.6f ms\n", icmp6len,
                     addr_str, icmp6->icmp6_seq, rtt);
            } else {
              printf("%d bytes from %s: seq=%u, rtt=%.3f ms\n", icmp6len,
                     addr_str, icmp6->icmp6_seq, rtt);
            }
          }
        }
      } else {
        /* try to resolve hostname from IPv6 address */
        struct hostent *hent;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)pr->sarecv;
        hent = gethostbyaddr(&sa6->sin6_addr, sizeof(sa6->sin6_addr), AF_INET6);
        if (hent != NULL) {
          inet_ntop(AF_INET6, &sa6->sin6_addr, addr_str, INET6_ADDRSTRLEN);
          if (!quiet) {
            if (user_latency) {
              if (rtt_precision) {
                printf("%d bytes from %s (%s): seq=%u, time=%.6f ms\n",
                       icmp6len, hent->h_name, addr_str, icmp6->icmp6_seq, rtt);
              } else {
                printf("%d bytes from %s (%s): seq=%u, time=%.3f ms\n",
                       icmp6len, hent->h_name, addr_str, icmp6->icmp6_seq, rtt);
              }
            } else {
              if (rtt_precision) {
                printf("%d bytes from %s (%s): seq=%u, rtt=%.6f ms\n", icmp6len,
                       hent->h_name, addr_str, icmp6->icmp6_seq, rtt);
              } else {
                printf("%d bytes from %s (%s): seq=%u, rtt=%.3f ms\n", icmp6len,
                       hent->h_name, addr_str, icmp6->icmp6_seq, rtt);
              }
            }
          }
        } else {
          if (!quiet) {
            if (user_latency) {
              if (rtt_precision) {
                printf("%d bytes from %s: seq=%u, time=%.6f ms\n", icmp6len,
                       Sock_ntop_host(pr->sarecv, pr->salen), icmp6->icmp6_seq,
                       rtt);
              } else {
                printf("%d bytes from %s: seq=%u, time=%.3f ms\n", icmp6len,
                       Sock_ntop_host(pr->sarecv, pr->salen), icmp6->icmp6_seq,
                       rtt);
              }
            } else {
              if (rtt_precision) {
                printf("%d bytes from %s: seq=%u, rtt=%.6f ms\n", icmp6len,
                       Sock_ntop_host(pr->sarecv, pr->salen), icmp6->icmp6_seq,
                       rtt);
              } else {
                printf("%d bytes from %s: seq=%u, rtt=%.3f ms\n", icmp6len,
                       Sock_ntop_host(pr->sarecv, pr->salen), icmp6->icmp6_seq,
                       rtt);
              }
            }
          }
        }
      }
    }

  } else if (verbose) {
    if (numeric_mode) {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)pr->sarecv)->sin6_addr,
                addr_str, INET6_ADDRSTRLEN);
      printf("  %d bytes from %s: type = %d, code = %d\n", icmp6len, addr_str,
             icmp6->icmp6_type, icmp6->icmp6_code);
    } else {
      printf("  %d bytes from %s: type = %d, code = %d\n", icmp6len,
             Sock_ntop_host(pr->sarecv, pr->salen), icmp6->icmp6_type,
             icmp6->icmp6_code);
    }
  } else {
    nrecv = 1; /* signing drop packet */
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
  icmp->icmp_id = pid & 0xFFFF;
  icmp->icmp_seq = nsent++;
  gettimeofday((struct timeval *)icmp->icmp_data, NULL);

  /* fill data with pattern if specified */
  if (pattern) {
    unsigned char *data = (unsigned char *)icmp->icmp_data + sizeof(struct timeval);
    int pattern_len = strlen(pattern) / 2;
    unsigned char pattern_bytes[pattern_len];

    /* convert hex string to bytes */
    for (int i = 0; i < pattern_len; i++) {
      sscanf(pattern + i * 2, "%2hhx", &pattern_bytes[i]);
    }

    /* fill data area with pattern */
    int data_size = datalen - sizeof(struct timeval);
    for (int i = 0; i < data_size; i++) {
      data[i] = pattern_bytes[i % pattern_len];
    }
  }

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
  icmp6->icmp6_id = pid & 0xFFFF;
  icmp6->icmp6_seq = nsent++;
  gettimeofday((struct timeval *)(icmp6 + 1), NULL);

  /* fill data with pattern if specified */
  if (pattern) {
    unsigned char *data = (unsigned char *)(icmp6 + 1) + sizeof(struct timeval);
    int pattern_len = strlen(pattern) / 2;
    unsigned char pattern_bytes[pattern_len];

    /* convert hex string to bytes */
    for (int i = 0; i < pattern_len; i++) {
      sscanf(pattern + i * 2, "%2hhx", &pattern_bytes[i]);
    }

    /* fill data area with pattern */
    int data_size = datalen - sizeof(struct timeval);
    for (int i = 0; i < data_size; i++) {
      data[i] = pattern_bytes[i % pattern_len];
    }
  }

  len = 8 + datalen; /* 8-byte ICMPv6 header */

  sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
  /* kernel calculates and stores checksum for us */
#endif /* IPV6 */
}

void readloop(void) {
  int size, tio_sign;
  char recvbuf[BUFSIZE];
  double p_inval;
  socklen_t len;
  ssize_t n;
  struct timeval tval;
  int nreceived = 0;
  int nsent_local = 0;
  int p_nsent = 0;
  struct timeval start, end, p_start, p_end;

  sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
  setuid(getuid()); /* don't need special permissions any more */

  size = 60 * 1024; /* OK if setsockopt fails */
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

  /* set send buffer size if specified */
  if (sndbuf_size > 0) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size,
                   sizeof(sndbuf_size)) < 0)
      err_sys("setsockopt SO_SNDBUF");
  }

  if (ttl > 0) {
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
  }
  if (broadcast) {
    int on = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
  }
  if (timeout > 0) {
    struct timeval tv;
    tv.tv_sec = (int)timeout;
    tv.tv_usec = (int)((timeout - (int)timeout) * 1000000);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  /* enable debug mode if requested */
  if (debug_mode) {
    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) < 0)
      err_sys("setsockopt SO_DEBUG");
  }

  /* set packet mark if specified */
  if (mark_value) {
#ifdef SO_MARK
    if (setsockopt(sockfd, SOL_SOCKET, SO_MARK, &mark_value,
                   sizeof(mark_value)) < 0)
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

    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu_val,
                   sizeof(pmtu_val)) < 0)
      err_sys("setsockopt IP_MTU_DISCOVER");
#else
    err_quit("IP_MTU_DISCOVER not supported on this system");
#endif
  }

  /* bind to specific interface if specified */
  if (interface) {
    /* try to bind by interface name */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface,
                   strlen(interface) + 1) < 0) {
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

  /* enable bypass routing if requested */
  if (bypass_route) {
    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on)) < 0)
      err_sys("setsockopt SO_DONTROUTE");
  }

  /* enable record route if requested (IPv4 only) */
  if (record_route && pr->sasend->sa_family == AF_INET) {
#ifdef IP_OPTIONS
    unsigned char rr_opt[40];
    memset(rr_opt, 0, sizeof(rr_opt));
    rr_opt[0] = IPOPT_RR; /* record route option */
    rr_opt[1] = 39;       /* option length */
    rr_opt[2] = 4;        /* pointer to first slot */

    if (setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, rr_opt, 39) == 0) {
      if (!quiet)
        printf("Record route option set\n");
    } else {
      if (!quiet)
        printf(
            "Warning: Record route option not supported by system/network\n");
    }
#else
    if (!quiet)
      printf("Warning: IP options not supported on this system\n");
#endif
  }

  /* set timestamp option if specified (IPv4 only) */
  if (timestamp_opt && pr->sasend->sa_family == AF_INET) {
#ifdef IP_OPTIONS
    unsigned char ts_opt[40];
    int ts_len;

    memset(ts_opt, 0, sizeof(ts_opt));
    ts_opt[0] = IPOPT_TIMESTAMP; /* timestamp option */

    if (strcmp(timestamp_opt, "tsonly") == 0) {
      ts_opt[1] = 36; /* option length */
      ts_opt[2] = 5;  /* pointer */
      ts_opt[3] = 0;  /* flags: timestamps only */
      ts_len = 36;
    } else if (strcmp(timestamp_opt, "tsandaddr") == 0) {
      ts_opt[1] = 36; /* option length */
      ts_opt[2] = 5;  /* pointer */
      ts_opt[3] = 1;  /* flags: timestamps and addresses */
      ts_len = 36;
    } else if (strcmp(timestamp_opt, "tsprespec") == 0) {
      ts_opt[1] = 36; /* option length */
      ts_opt[2] = 5;  /* pointer */
      ts_opt[3] = 3;  /* flags: prespecified addresses */
      ts_len = 36;
    }

    if (setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, ts_opt, ts_len) < 0)
      err_sys("setsockopt IP_OPTIONS (timestamp)");
#else
    err_quit("IP timestamp options not supported on this system");
#endif
  }

  gettimeofday(&start, NULL);

  nsent = 0;
  nreceived = 0;
  preceived = 0;
  nrecv = 0;

  /* preload packets if specified */
  if (preload_count > 0) {
    for (int i = 0; i < preload_count; i++) {
      (*pr->fsend)();
    }
  }

  sig_alrm(SIGALRM); /* send first packet */

  /* Choose readloop implementation based on ping1 vs ping2 approach */
  if (count > 0 || timeout > 0) {
    /* ping1 style loop with timeout and count handling */
    for (;;) {
      /* count packets sent */
      if (count > 0 && nsent >= count)
        break;

      /* wait for packet with timeout */
      len = pr->salen;
      struct timeval recv_timeout;
      recv_timeout.tv_sec = (int)timeout;
      recv_timeout.tv_usec = (int)((timeout - (int)timeout) * 1000000);
      
      fd_set readfds;
      FD_ZERO(&readfds);
      FD_SET(sockfd, &readfds);
      
      int ready = select(sockfd + 1, &readfds, NULL, NULL, &recv_timeout);
      if (ready < 0) {
        if (errno == EINTR)
          continue;
        else
          err_sys("select error");
      } else if (ready == 0) {
        /* timeout occurred */
        if (!quiet)
          printf("Exceed timeLimit\n");
        preceived++;
        continue;
      }

      n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
      if (n < 0) {
        if (errno == EINTR)
          continue;
        else
          err_sys("recvfrom error");
      }

      gettimeofday(&tval, NULL);
      nreceived++;
      (*pr->fproc)(recvbuf, n, &tval);
      
      /* drop other packet that do not belong target addr */
      if (nrecv) {
        nreceived--;
        nrecv = 0;
      }
    }
    gettimeofday(&end, NULL);

    double elapsed =
        (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("--- %s ping statistics ---\n", host);
    printf("%d packets transmitted, %d received, %.1f%% packet loss, time %.3f "
           "s\n",
           nsent, nreceived - preceived,
           nsent ? 100.0 * preceived / nsent : 0.0, elapsed);
    
    /* Print RTT statistics if we have valid data */
    if (rtt_count > 0) {
      double rtt_avg = rtt_sum / rtt_count;
      double rtt_mdev = 0.0;
      if (rtt_count > 1) {
        double variance = (rtt_sum_sq / rtt_count) - (rtt_avg * rtt_avg);
        rtt_mdev = sqrt(variance > 0 ? variance : 0);
      }
      printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
             rtt_min, rtt_avg, rtt_max, rtt_mdev);
    }
  } else {
    /* ping2 style simple loop */
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
}

void sig_alrm(int signo) {
  static time_t start_time = 0;

  /* initialize start time */
  if (start_time == 0) {
    start_time = time(NULL);
  }

  /* handle deadline timeout */
  if (deadline > 0 && (time(NULL) - start_time) >= deadline) {
    printf("\n--- %s ping statistics ---\n", host);
    printf("%d packets transmitted, statistics not available\n", nsent);
    exit(0);
  }

  /* handle count limit */
  if (count > 0 && nsent >= count)
    return;

  (*pr->fsend)();

  /* set alarm interval based on flood mode */
  if (flood_mode) {
    /* flood mode: send as fast as possible without recursion */
    struct itimerval timer;
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 10000; /* 10ms interval for flood mode */
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 10000;
    setitimer(ITIMER_REAL, &timer, NULL);
  } else {
    alarm((unsigned int)interval);
  }
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

  if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo error for %s: %s\n", host, gai_strerror(n));
    return (NULL);
  }

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

void usage(void) {
  printf("Usage: ping [options] <hostname>\n");
  printf("Options:\n");
  printf("  -b           Allow pinging a broadcast address\n");
  printf("  -c count     Stop after sending count packets\n");
  printf("  -h           Show this help message\n");
  printf("  -i interval  Wait interval seconds between sending each packet "
         "(default 1)\n");
  printf("  -q           Quiet output (summary only)\n");
  printf("  -s size      Number of data bytes to be sent\n");
  printf("  -t ttl       Set IP Time To Live\n");
  printf("  -v           Verbose output\n");
  printf(
      "  -W timeout   Time to wait for a response, in seconds (default 1)\n");
  printf("  -4           Force IPv4\n");
  printf("  -6           Force IPv6\n");
  printf("  -d           Enable SO_DEBUG\n");
  printf("  -m mark      Set packet mark value\n");
  printf("  -M pmtudisc  Path MTU Discovery mode (do/dont/want/probe)\n");
  printf("  -I interface Network interface or IP address\n");
  printf("  -T tstamp    Timestamp option (tsonly/tsandaddr/tsprespec)\n");
  printf("  -f           Flood ping mode\n");
  printf("  -n           Numeric output mode\n");
  printf("  -p pattern   Fill pattern in hex\n");
  printf("  -r           Bypass routing table\n");
  printf("  -R           Record route\n");
  printf("  -l preload   Preload count\n");
  printf("  -w deadline  Deadline in seconds\n");
  printf("  -V           Print version and exit\n");
  printf("  -3           RTT precision (do not round up the result time)\n");
  printf("  -D           Print timestamps\n");
  printf("  -U           Print user-to-user latency (use 'time' instead of "
         "'rtt')\n");
  printf("  -S size      Use size as SO_SNDBUF socket option value\n");
}

void print_version(void) {
  printf("ping version %s\n", PING_VERSION);
  printf("Compiled with IPv6 support\n");
  printf("Copyright (C) 2024. This is free software.\n");
}

void print_timestamp(void) {
  struct timeval tv;
  struct tm *tm_info;
  char timestamp[32];

  gettimeofday(&tv, NULL);
  tm_info = localtime(&tv.tv_sec);
  strftime(timestamp, sizeof(timestamp), "[%H:%M:%S", tm_info);
  printf("%s.%06ld] ", timestamp, tv.tv_usec);
}

/* Returns 1 if addr is a broadcast address, 0 otherwise */
int is_broadcast_ip(const struct sockaddr_in *addr) {
  /* Check for limited broadcast address 255.255.255.255 */
  if (addr->sin_addr.s_addr == INADDR_BROADCAST) {
    return 1;
  }
  
  /* Check for subnet broadcast address by examining the last octet */
  uint32_t ip_addr = ntohl(addr->sin_addr.s_addr);
  uint8_t last_octet = ip_addr & 0xFF;
  
  /* Common subnet broadcast patterns (ending in 255) */
  if (last_octet == 255) {
    return 1;
  }
  
  return 0;
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
