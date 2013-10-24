#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ndelay.h"
#include "select.h"
#include "error.h"
#include "readwrite.h"
#include "ip.h"
#include "byte.h"
#include "timeoutconn.h"
#include "constmap.h"
#include "control.h"
#include "stralloc.h"
#include "ipalloc.h"
#include "str.h"

#ifndef BIND_SOCKET_ERROR
#define BIND_SOCKET_ERROR 1 /* 0 to ignore bind fail, 1 to tempfail and requeue */
#endif

struct ip_mx ixlocal;
int bindlocal = 0;

/* return 1 for success otherwise return 0 */
int ip_mx_init(ix)
struct ip_mx *ix;
{
#ifdef INET6
  byte_copy(&ix->addr.ip6.d, 16, V6any);
  if (byte_equal(&ix->addr.ip6.d, 16, V6any) == 0) return 0;
#endif
  byte_copy(&ix->addr.ip.d, 4, V6any);
  if (byte_equal(&ix->addr.ip.d, 4, V6any) == 0) return 0;
  return 1;
}

/* get current ixlocal address
 * return -1 if copy ixlocal into oix failed
 * otherwise return bindlocal=0|1
 */
int get_bind_ixlocal(oix)
struct ip_mx *oix;
{
  oix->af = ixlocal.af;
#ifdef INET6
  byte_copy(&oix->addr.ip6.d,16,&ixlocal.addr.ip6.d);
  if (!byte_equal(&oix->addr.ip6.d,16,&ixlocal.addr.ip6.d)) return -1;
#endif
  byte_copy(&oix->addr.ip.d,4,&ixlocal.addr.ip.d);
  if (!byte_equal(&oix->addr.ip.d,4,&ixlocal.addr.ip.d)) return -1;
  return 1;
}

/* change outgoing ip i.e. copy oix to ixlocal
 * return 1 for success
 * if already set ixlocal due to bindlocal return 0
 * if initialize ixlocal failed, return -1 instead
 * if copy oix to ixlocal failed, return -2
 */
int bind_by_changeoutgoingip(oix,force)
struct ip_mx *oix;
int force;
{
  if (!bindlocal) {
    if (ip_mx_init(&ixlocal) == 0) return -1;
  }
  if (!force) if (bindlocal) return 0; /* already bind so we skip it */
#ifdef INET6
  if (!byte_equal(&oix->addr.ip6.d,16,V6any)) {
    byte_copy(&ixlocal.addr.ip6.d,16,&oix->addr.ip6.d);
    if (!byte_equal(&ixlocal.addr.ip6.d,16,&oix->addr.ip6.d)) return -2;
  }
#endif
  if (!byte_equal(&oix->addr.ip.d,4,V6any)) {
    byte_copy(&ixlocal.addr.ip.d,4,&oix->addr.ip.d);
    if (!byte_equal(&ixlocal.addr.ip.d,4,&oix->addr.ip.d)) return -2;
  }
#ifdef INET6
  if (oix->af == AF_INET6) {
    ixlocal.af = AF_INET6;
    bindlocal = 1;
  } else {
    ixlocal.af = AF_INET;
    bindlocal = 1;
  }
#else
  ixlocal.af = AF_INET;
  bindlocal = 1;
#endif
  return bindlocal;
}

/* Modified from http://qmail.org/local-bind
 * return 1 if successfully set ixlocal otherwise return 0
 * if initialize ixlocal failed, return -1 instead
 */
int bind_by_bindroutes(ix,force)
struct ip_mx *ix;
int force;
{
  if (!bindlocal) {
    if (ip_mx_init(&ixlocal) == 0) return -1;
  }
  if (!force) if (bindlocal) return 0; /* already bind so we skip it */

  char *ipstr, ipstring[IPFMT+1];
  int iplen;
  stralloc routes = {0};
  struct constmap bindroutes;
  char *bindroute = (char *)0;

#ifdef INET6
  if (ix->af == AF_INET6) {
    /* Right, do we actually have any bind routes? */
    switch(control_readfile(&routes,"control/bindroutes6",0))
    {
      case 0: return 0; /* no file, no bind to worry about */
      case -1: return -2; /* buggered up somewhere, urgh! */
      case 1: if (!constmap_init_char(&bindroutes,routes.s,routes.len,1,'|')) return -3;
    }
  } else {
    /* Right, do we actually have any bind routes? */
    switch(control_readfile(&routes,"control/bindroutes",0))
    {
      case 0: return 0; /* no file, no bind to worry about */
      case -1: return -2; /* buggered up somewhere, urgh! */
      case 1: if (!constmap_init_char(&bindroutes,routes.s,routes.len,1,'|')) return -3;
    }
  }
#else
  /* Right, do we actually have any bind routes? */
  switch(control_readfile(&routes,"control/bindroutes",0))
  {
    case 0: return 0; /* no file, no bind to worry about */
    case -1: return -2; /* buggered up somewhere, urgh! */
    case 1: if (!constmap_init_char(&bindroutes,routes.s,routes.len,1,'|')) return -3;
  }
#endif
  ipstring[0] = '.'; /* "cheating", but makes the loop check easier below! */
  ipstr = ipstring+1;
#ifdef INET6
  if (ix->af == AF_INET6) {
    iplen = ip6_fmt(ipstr,&ix->addr.ip6);
  } else {
    iplen = ip_fmt(ipstr,&ix->addr.ip);
  }
#else
  iplen = ip_fmt(ipstr,&ix->addr.ip); /* Well, Dan seems to trust its output! */
#endif

  /* check d.d.d.d, d.d.d., d.d., d., none for IPv4 */
  /* check ':' colon character for IPv6 */
  bindroute = constmap(&bindroutes,ipstr,iplen);
  if (!bindroute) while (iplen--)  /* no worries - the lost char must be 0-9 */
    if (ipstring[iplen] == '.' || ipstring[iplen] == ':')
      if (bindroute = constmap(&bindroutes,ipstr,iplen)) break;
  if (!bindroute || !*bindroute) return 0; /* no bind required */
#ifdef INET6
  if (ix->af == AF_INET6) {
    if (!ip6_scan(bindroute,&ixlocal.addr.ip6)) return -4; /* wasn't an ipv6 returned */
    ixlocal.af = AF_INET6;
    bindlocal = 1;
  } else {
    if (!ip_scan(bindroute,&ixlocal.addr.ip)) return -4; /* wasn't an ip returned */
    ixlocal.af = AF_INET;
    bindlocal = 1;
  }
#else
  if (!ip_scan(bindroute,&ixlocal.addr.ip)) return -4; /* wasn't an ip returned */
  ixlocal.af = AF_INET;
  bindlocal = 1;
#endif
  return 0;
}

int timeoutconn(s,ip,port,timeout)
int s;
struct ip_address *ip;
unsigned int port;
int timeout;
{
  char ch;
  struct sockaddr_in sin;
  struct sockaddr_in salocal;
  char *x;
  fd_set wfds;
  struct timeval tv;

  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin_addr,4,ip);
  x = (char *) &sin.sin_port;
  x[1] = port; port >>= 8; x[0] = port;
  sin.sin_family = AF_INET;

  if (ndelay_on(s) == -1) return -1;
 
  /* if bindlocal is non-zero, we bind ixlocal.addr.ip as outgoing ip instead */
  if (bindlocal) {
    byte_zero(&salocal,sizeof(salocal));
    salocal.sin_family = AF_INET;
    byte_copy(&salocal.sin_addr,4,&ixlocal.addr.ip);
    if (bind(s, (struct sockaddr *)&salocal,sizeof(salocal))) {
      if (BIND_SOCKET_ERROR) return errno;
    }
  }

  if (connect(s,(struct sockaddr *) &sin,sizeof(sin)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != error_inprogress) && (errno != error_wouldblock)) return -1;

  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;

  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(sin);
    if (getpeername(s,(struct sockaddr *) &sin,&dummy) == -1) {
      read(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }

  errno = error_timeout; /* note that connect attempt is continuing */
  return -1;
}

#ifdef INET6
int timeoutconn6(s,ip,port,timeout)
int s;
struct ip6_address *ip;
unsigned int port;
int timeout;
{
  char ch;
  struct sockaddr_in6 sin;
  struct sockaddr_in6 salocal;
  char *x;
  fd_set wfds;
  struct timeval tv;

  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin6_addr,16,ip);
  sin.sin6_port = htons(port);
  sin.sin6_family = AF_INET6;

  if (ndelay_on(s) == -1) return -1;

  /* if bindlocal is non-zero, we bind ixlocal.addr.ip6 as outgoing ip instead */
  if (bindlocal) {
    byte_zero(&salocal,sizeof(salocal));
    byte_copy(&salocal.sin6_addr,16,&ixlocal.addr.ip6);
    // salocal.sin6_port = htons(port); /* is this needed? */
    salocal.sin6_family = AF_INET6;
    if (bind(s, (struct sockaddr *)&salocal,sizeof(salocal))) {
      if (BIND_SOCKET_ERROR) return errno;
    }
  }

  if (connect(s,(struct sockaddr *) &sin,sizeof(sin)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != error_inprogress) && (errno != error_wouldblock)) return -1;

  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;

  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(sin);
    if (getpeername(s,(struct sockaddr *) &sin,&dummy) == -1) {
      read(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }

  errno = error_timeout; /* note that connect attempt is continuing */
  return -1;
}
#endif
