#include "fmt.h"
#include "scan.h"
#include "ip.h"
#include "byte.h"

unsigned int ip_fmt(s,ip)
char *s;
struct ip_address *ip;
{
  unsigned int len;
  unsigned int i;
 
  len = 0;
  i = fmt_ulong(s,(unsigned long) ip->d[0]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip->d[1]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip->d[2]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip->d[3]); len += i; if (s) s += i;
  return len;
}

unsigned int ip_scan(s,ip)
char *s;
struct ip_address *ip;
{
  unsigned int i;
  unsigned int len;
  unsigned long u;
 
  len = 0;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[0] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[1] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[2] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[3] = u; s += i; len += i;
  return len;
}

unsigned int ip_scanbracket(s,ip)
char *s;
struct ip_address *ip;
{
  unsigned int len;
 
  if (*s != '[') return 0;
  len = ip_scan(s + 1,ip);
  if (!len) return 0;
  if (s[len + 1] != ']') return 0;
  return len + 2;
}

#ifdef INET6
/* copy and modify from fefe's djbdns IPv6 patch ip6_scan.c
 * http://www.fefe.de/dns/djbdns-1.05-test25.diff.bz2
 * see http://www.fefe.de/dns/
 */
/*
 * IPv6 addresses are really ugly to parse.
 * Syntax: (h = hex digit)
 *   1. hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh
 *   2. any number of 0000 may be abbreviated as "::", but only once
 *   3. The last two words may be written as IPv4 address
 */

unsigned int ip6_scan(const char *s,struct ip6_address *ip)
{
  unsigned int i;
  unsigned int len=0;
  unsigned long u;

  char suffix[16];
  int prefixlen=0;
  int suffixlen=0;

  unsigned int x;
  struct ip_address ip4;

  for (x=0; x<4; x++) {
    ip4.d[x] = ip->d[x+12];
  }

  if ((i=ip4_scan(s,&ip4))) {
    const char *c=V4mappedprefix;
    if (byte_equal(ip4.d,4,V6any)) c=V6any;
    for (len=0; len<12; ++len) ip->d[len]=c[len];
    return i;
  }
  for (i=0; i<16; i++) ip->d[i]=0;
  for (;;) {
    if (*s == ':') {
      len++;
      if (s[1] == ':') {	/* Found "::", skip to part 2 */
        s+=2;
        len++;
        break;
      }
      s++;
    }
    i = scan_xlong(s,&u);
    if (!i) return 0;
    if (prefixlen==12 && s[i]=='.') {
      /* the last 4 bytes may be written as IPv4 address */
      i=ip4_scan(s,&ip4);
      if (i) {
        /* copy into ip->d+12 from ip4 */
        for (x=0; x<4; x++) {
          ip->d[x+12] = ip4.d[x];
        }
        return i+len;
      } else
        return 0;
    }
    ip->d[prefixlen++] = (u >> 8);
    ip->d[prefixlen++] = (u & 255);
    s += i; len += i;
    if (prefixlen==16)
      return len;
  }

/* part 2, after "::" */
  for (;;) {
    if (*s == ':') {
      if (suffixlen==0)
	break;
      s++;
      len++;
    } else if (suffixlen!=0)
      break;
    i = scan_xlong(s,&u);
    if (!i) {
      len--;
      break;
    }
    if (suffixlen+prefixlen<=12 && s[i]=='.') {
      int j=ip4_scan(s,&ip4);
      if (j) {
        byte_copy(suffix+suffixlen,4,ip4.d);
	suffixlen+=4;
	len+=j;
	break;
      } else
        prefixlen=12-suffixlen; /* make end-of-loop test true */
    }
    suffix[suffixlen++] = (u >> 8);
    suffix[suffixlen++] = (u & 255);
    s += i; len += i;
    if (prefixlen+suffixlen==16)
      break;
  }
  for (i=0; i<suffixlen; i++)
    ip->d[16-suffixlen+i] = suffix[i];
  return len;
}

static long int fromhex(unsigned char c) {
  if (c>='0' && c<='9')
    return c-'0';
  else if (c>='A' && c<='F')
    return c-'A'+10;
  else if (c>='a' && c<='f')
    return c-'a'+10;
  return -1;
}

unsigned int ip6_scan_flat(const char *s,struct ip6_address *ip)
{
  int i;
  for (i=0; i<16; i++) {
    int tmp;
    tmp=fromhex(*s++);
    if (tmp<0) return 0;
    ip->d[i]=tmp << 4;
    tmp=fromhex(*s++);
    if (tmp<0) return 0;
    ip->d[i]+=tmp;
  }
  return 32;
}

/* copy and modify from fefe's djbdns IPv6 patch ip6_fmt.c
 * http://www.fefe.de/dns/djbdns-1.05-test25.diff.bz2
 * see http://www.fefe.de/dns/
 */
extern char tohex(char num);

unsigned int ip6_fmt(char *s,struct ip6_address *ip)
{
  unsigned int len;
  unsigned int i;
  unsigned int temp;
  unsigned int compressing;
  unsigned int compressed;
  int j;
  struct ip_address ip4;

  len = 0; compressing = 0; compressed = 0;
  for (j=0; j<16; j+=2) {
    if (j==12 && ip6_isv4mapped(ip->d)) {
      for (i=0; i<4; i++) {
        ip4.d[i] = ip->d[i+12];
      }
      temp=ip4_fmt(s,&ip4);
      len+=temp;
      break;
    }
    temp = ((unsigned long) (unsigned char) ip->d[j] << 8) +
            (unsigned long) (unsigned char) ip->d[j+1];
    if (temp == 0 && !compressed) {
      if (!compressing) {
	compressing=1;
	if (j==0) {
	  if (s) *s++=':'; ++len;
	}
      }
    } else {
      if (compressing) {
	compressing=0; ++compressed;
	if (s) *s++=':'; ++len;
      }
      i = fmt_xlong(s,temp); len += i; if (s) s += i;
      if (j<14) {
	if (s) *s++ = ':';
	++len;
      }
    }
  }
  if (compressing) { *s++=':'; ++len; }

/*  if (s) *s=0; */
  return len;
}

unsigned int ip6_fmt_flat(char *s,struct ip6_address *ip)
{
  int i;
  for (i=0; i<16; i++) {
    *s++=tohex((unsigned char)ip->d[i] >> 4);
    *s++=tohex((unsigned char)ip->d[i] & 15);
  }
  return 32;
}
#endif
