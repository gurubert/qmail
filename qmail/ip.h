#ifndef IP_H
#define IP_H

struct ip_address { unsigned char d[4]; } ;
#ifdef INET6
struct ip6_address { unsigned char d[16]; } ;
#endif

extern unsigned int ip_fmt();
#ifdef INET6
/* copy and modify from fefe's djbdns IPv6 patch ip6.h
 * http://www.fefe.de/dns/djbdns-1.05-test25.diff.bz2
 * see http://www.fefe.de/dns/
 */
extern unsigned int ip6_scan();
extern unsigned int ip6_fmt();

extern unsigned int ip6_scan_flat();
extern unsigned int ip6_fmt_flat();

/*
 ip6 address syntax: (h = hex digit), no leading '0' required
   1. hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh
   2. any number of 0000 may be abbreviated as "::", but only once
 flat ip6 address syntax:
   hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
 */

#define IP6_FMT 40

const static unsigned char V4mappedprefix[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
const static unsigned char V6loopback[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const static unsigned char V6any[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

#define ip6_isv4mapped(ip) (byte_equal(ip,12,V4mappedprefix))

const static char ip4loopback[4] = {127,0,0,1};
#define ip4_scan(a,b) ip_scan(a,b)
#define ip4_fmt(a,b) ip_fmt(a,b)

#define IPFMT 72
#else
#define IPFMT 19
#endif
extern unsigned int ip_scan();
extern unsigned int ip_scanbracket();
#define HOSTNAMELEN	1025

#endif
