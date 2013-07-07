#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sig.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "scan.h"
#include "case.h"
#include "error.h"
#include "auto_qmail.h"
#include "control.h"
#include "dns.h"
#include "alloc.h"
#include "quote.h"
#include "ip.h"
#include "ipalloc.h"
#include "ipme.h"
#include "gen_alloc.h"
#include "gen_allocdefs.h"
#include "str.h"
#include "now.h"
#include "exit.h"
#include "constmap.h"
#include "tcpto.h"
#include "readwrite.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"

#define HUGESMTPTEXT 5000

#define PORT_SMTP 25 /* silly rabbit, /etc/services is for users */
unsigned long port = PORT_SMTP;

GEN_ALLOC_typedef(saa,stralloc,sa,len,a)
GEN_ALLOC_readyplus(saa,stralloc,sa,len,a,i,n,x,10,saa_readyplus)
static stralloc sauninit = {0};

stralloc helohost = {0};
stralloc routes = {0};
struct constmap maproutes;
stralloc host = {0};
stralloc sender = {0};

saa reciplist = {0};

struct ip_mx partner;

void out(s) char *s; { if (substdio_puts(subfdoutsmall,s) == -1) _exit(0); }
void zero() { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(0); }
void zerodie() { zero(); substdio_flush(subfdoutsmall); _exit(0); }
void outsafe(sa) stralloc *sa; { int i; char ch;
for (i = 0;i < sa->len;++i) {
ch = sa->s[i]; if (ch < 33) ch = '?'; if (ch > 126) ch = '?';
if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(0); } }

#ifdef INET6
void temp_badip6() { out("Z\
Unable to parse IPv6 address in control/domainbindings6 (#4.3.0)\n"); zerodie(); }
void temp_noip6() { out("Zinvalid IPv6 address in control/outgoingip6 (#4.3.0)\n"); zerodie(); }
#endif
void temp_badip() { out("Z\
Unable to parse IP address in control/domainbindings (#4.3.0)\n"); zerodie(); }
void temp_noip() { out("Zinvalid IPv4 address in control/outgoingip (#4.3.0)\n"); zerodie(); }
void temp_nobind1() { out("ZUnable to initialize ixlocal (-1). (#4.3.0)\n"); zerodie(); }
void temp_nobind2() { out("ZUnable to set ixlocal (-2). (#4.3.0)\n"); zerodie(); }
void temp_nomem() { out("ZOut of memory. (#4.3.0)\n"); zerodie(); }
void temp_oserr() { out("Z\
System resources temporarily unavailable. (#4.3.0)\n"); zerodie(); }
void temp_noconn() { out("Z\
Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)\n"); zerodie(); }
void temp_read() { out("ZUnable to read message. (#4.3.0)\n"); zerodie(); }
void temp_dnscanon() { out("Z\
CNAME lookup failed temporarily. (#4.4.3)\n"); zerodie(); }
void temp_dns() { out("Z\
Sorry, I couldn't find any host by that name. (#4.1.2)\n"); zerodie(); }
void temp_chdir() { out("Z\
Unable to switch to home directory. (#4.3.0)\n"); zerodie(); }
void temp_control() { out("Z\
Unable to read control files. (#4.3.0)\n"); zerodie(); }
void perm_partialline() { out("D\
SMTP cannot transfer messages with partial final lines. (#5.6.2)\n"); zerodie(); }
void perm_usage() { out("D\
I (qmail-remote) was invoked improperly. (#5.3.5)\n"); zerodie(); }
void perm_dns() { out("D\
Sorry, I couldn't find any host named ");
outsafe(&host);
out(". (#5.1.2)\n"); zerodie(); }
void perm_nomx() { out("D\
Sorry, I couldn't find a mail exchanger or IP address. (#5.4.4)\n");
zerodie(); }
void perm_ambigmx() { out("D\
Sorry. Although I'm listed as a best-preference MX or A for that host,\n\
it isn't in my control/locals file, so I don't treat it as local. (#5.4.6)\n");
zerodie(); }

void outhost()
{
  char x[IPFMT];
#ifdef INET6
  if (partner.af == AF_INET) {
#endif
  if (substdio_put(subfdoutsmall,x,ip_fmt(x,&partner.addr.ip)) == -1) _exit(0);
#ifdef INET6
  } else {
  if (substdio_put(subfdoutsmall,x,ip6_fmt(x,&partner.addr.ip6)) == -1) _exit(0);
  }
#endif
}

int flagcritical = 0;

void dropped() {
  out("ZConnected to ");
  outhost();
  out(" but connection died. ");
  if (flagcritical) out("Possible duplicate! ");
  out("(#4.4.2)\n");
  zerodie();
}

int timeoutconnect = 60;
int smtpfd;
int timeout = 1200;

int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutread(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}
int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutwrite(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}

char inbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(read,0,inbuf,sizeof inbuf);
char smtptobuf[1024];
substdio smtpto = SUBSTDIO_FDBUF(safewrite,-1,smtptobuf,sizeof smtptobuf);
char smtpfrombuf[128];
substdio smtpfrom = SUBSTDIO_FDBUF(saferead,-1,smtpfrombuf,sizeof smtpfrombuf);

stralloc smtptext = {0};

void get(ch)
char *ch;
{
  substdio_get(&smtpfrom,ch,1);
  if (*ch != '\r')
    if (smtptext.len < HUGESMTPTEXT)
     if (!stralloc_append(&smtptext,ch)) temp_nomem();
}

unsigned long smtpcode()
{
  unsigned char ch;
  unsigned long code;

  if (!stralloc_copys(&smtptext,"")) temp_nomem();

  get(&ch); code = ch - '0';
  get(&ch); code = code * 10 + (ch - '0');
  get(&ch); code = code * 10 + (ch - '0');
  for (;;) {
    get(&ch);
    if (ch != '-') break;
    while (ch != '\n') get(&ch);
    get(&ch);
    get(&ch);
    get(&ch);
  }
  while (ch != '\n') get(&ch);

  return code;
}

void outsmtptext()
{
  int i; 
  if (smtptext.s) if (smtptext.len) {
    out("Remote host said: ");
    for (i = 0;i < smtptext.len;++i)
      if (!smtptext.s[i]) smtptext.s[i] = '?';
    if (substdio_put(subfdoutsmall,smtptext.s,smtptext.len) == -1) _exit(0);
    smtptext.len = 0;
  }
}

void quit(prepend,append)
char *prepend;
char *append;
{
  substdio_putsflush(&smtpto,"QUIT\r\n");
  /* waiting for remote side is just too ridiculous */
  out(prepend);
  outhost();
  out(append);
  out(".\n");
  outsmtptext();
  zerodie();
}

void blast()
{
  int r;
  char ch;

  for (;;) {
    r = substdio_get(&ssin,&ch,1);
    if (r == 0) break;
    if (r == -1) temp_read();
    if (ch == '.')
      substdio_put(&smtpto,".",1);
    while (ch != '\n') {
      substdio_put(&smtpto,&ch,1);
      r = substdio_get(&ssin,&ch,1);
      if (r == 0) perm_partialline();
      if (r == -1) temp_read();
    }
    substdio_put(&smtpto,"\r\n",2);
  }
 
  flagcritical = 1;
  substdio_put(&smtpto,".\r\n",3);
  substdio_flush(&smtpto);
}

stralloc recip = {0};

void smtp()
{
  unsigned long code;
  int flagbother;
  int i;
 
  if (smtpcode() != 220) quit("ZConnected to "," but greeting failed");
 
  substdio_puts(&smtpto,"HELO ");
  substdio_put(&smtpto,helohost.s,helohost.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 250) quit("ZConnected to "," but my name was rejected");
 
  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,">\r\n");
  substdio_flush(&smtpto);
  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was rejected");
 
  flagbother = 0;
  for (i = 0;i < reciplist.len;++i) {
    substdio_puts(&smtpto,"RCPT TO:<");
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_puts(&smtpto,">\r\n");
    substdio_flush(&smtpto);
    code = smtpcode();
    if (code >= 500) {
      out("h"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else if (code >= 400) {
      out("s"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else {
      out("r"); zero();
      flagbother = 1;
    }
  }
  if (!flagbother) quit("DGiving up on ","");
 
  substdio_putsflush(&smtpto,"DATA\r\n");
  code = smtpcode();
  if (code >= 500) quit("D"," failed on DATA command");
  if (code >= 400) quit("Z"," failed on DATA command");
 
  blast();
  code = smtpcode();
  flagcritical = 0;
  if (code >= 500) quit("D"," failed after I sent the message");
  if (code >= 400) quit("Z"," failed after I sent the message");
  quit("K"," accepted message");
}

stralloc canonhost = {0};
stralloc canonbox = {0};

void addrmangle(saout,s,flagalias,flagcname)
stralloc *saout; /* host has to be canonical, box has to be quoted */
char *s;
int *flagalias;
int flagcname;
{
  int j;
 
  *flagalias = flagcname;
 
  j = str_rchr(s,'@');
  if (!s[j]) {
    if (!stralloc_copys(saout,s)) temp_nomem();
    return;
  }
  if (!stralloc_copys(&canonbox,s)) temp_nomem();
  canonbox.len = j;
  if (!quote(saout,&canonbox)) temp_nomem();
  if (!stralloc_cats(saout,"@")) temp_nomem();
 
  if (!stralloc_copys(&canonhost,s + j + 1)) temp_nomem();
  if (flagcname)
    switch(dns_cname(&canonhost)) {
      case 0: *flagalias = 0; break;
      case DNS_MEM: temp_nomem();
      case DNS_SOFT: temp_dnscanon();
      case DNS_HARD: ; /* alias loop, not our problem */
    }

  if (!stralloc_cat(saout,&canonhost)) temp_nomem();
}

/* return 1 if need to change ip otherwise return 0
 * if initialize outix failed, return -1 instead
 */
int getcontrol_outgoingip(ix)
struct ip_mx *ix;
{
  struct ip_mx outix;
  /* initialize outix first */
  if (!ip_mx_init(&outix)) return -1;
  stralloc outipsa = {0};
  int r;
  int outgoingipok = 0;
  /* for IPv4 is control/outgoingip and IPv6 is control/outgoingip6 */
#ifdef INET6
  int x = 0;
  if (ix->af == AF_INET6) {
    r = control_readline(&outipsa,"control/outgoingip6");
    if (-1 == r) { if (errno == error_nomem) temp_nomem(); temp_control(); }
    if (0 == r && !stralloc_copys(&outipsa, "0000:0000:0000:0000:0000:0000:0000:0000")) temp_nomem();
    /* http://tools.ietf.org/html/rfc3513#section-2.5.2 The Unspecified Address */
    /* 0:0:0:0:0:0:0:0 or :: or ::0 or ::/128 or ::0/128 or 0000::0/128 */
    /* NOTE: currently not support parsing IPv6 with '/' character */
    if (str_equal(outipsa.s, "0:0:0:0:0:0:0:0") ||
        str_equal(outipsa.s, "::") ||
        str_equal(outipsa.s, "::0") ||
        str_equal(outipsa.s, "::/128") ||
        str_equal(outipsa.s, "::0/128") ||
        str_equal(outipsa.s, "0000::0/128") ||
        str_equal(outipsa.s, "0000:0000:0000:0000:0000:0000:0000:0000")) {
      if (!stralloc_copys(&outipsa, "0000:0000:0000:0000:0000:0000:0000:0000")) temp_nomem();
      if (!ip6_scan(outipsa.s, &outix.addr.ip6)) temp_noip6();
      x++;
    } else {
      if (!ip6_scan(outipsa.s, &outix.addr.ip6)) temp_noip6();
      x++;
    }
    if (x > 0) {
      char ipstr[IPFMT];
      int iplen = 0;
      iplen = ip6_fmt(ipstr, &outix.addr.ip6);
      ipstr[iplen] = 0;
      if (iplen > 0 && !str_equal(ipstr,"0:0:0:0:0:0:0:0")
        && !str_equal(ipstr,"::") && !str_equal(ipstr,"::0")
        && !str_equal(ipstr, "0000:0000:0000:0000:0000:0000:0000:0000")) {
        outix.af = ix->af;
        outgoingipok = 1;
      }
    }
  } else {
    r = control_readline(&outipsa,"control/outgoingip");
    if (-1 == r) { if (errno == error_nomem) temp_nomem(); temp_control(); }
    if (0 == r && !stralloc_copys(&outipsa, "0.0.0.0")) temp_nomem();
    /* IPv4 The Unspecified Address is 0.0.0.0 */
    if (str_equal(outipsa.s, "0.0.0.0")) {
      outix.addr.ip.d[0] = outix.addr.ip.d[1] = outix.addr.ip.d[2] = outix.addr.ip.d[3] = (unsigned long)0;
    }
    else if (!ip_scan(outipsa.s, &outix.addr.ip)) temp_noip();
    if (outix.addr.ip.d[0] || outix.addr.ip.d[1] || outix.addr.ip.d[2] || outix.addr.ip.d[3]) {
      if (!ipme_is(&outix.addr.ip)) temp_noip();
      outix.af = ix->af;
      outgoingipok = 1;
    }
  }
#else
  r = control_readline(&outipsa,"control/outgoingip");
  if (-1 == r) { if (errno == error_nomem) temp_nomem(); temp_control(); }
  if (0 == r && !stralloc_copys(&outipsa, "0.0.0.0")) temp_nomem();
  if (str_equal(outipsa.s, "0.0.0.0")) {
    outix.addr.ip.d[0] = outix.addr.ip.d[1] = outix.addr.ip.d[2] = outix.addr.ip.d[3] = (unsigned long)0;
  }
  else if (!ip_scan(outipsa.s, &outix.addr.ip)) temp_noip();
  if (outix.addr.ip.d[0] || outix.addr.ip.d[1] || outix.addr.ip.d[2] || outix.addr.ip.d[3]) {
    if (!ipme_is(&outix.addr.ip)) temp_noip();
    outix.af = ix->af;
    outgoingipok = 1;
  }
#endif
  if (outgoingipok > 0) {
    return bind_by_changeoutgoingip(&outix, 0);
  }
  return 0;
}

/* return 1 if need to change ip otherwise return 0
 * if initialize outix failed, return -1 instead
 */
int getcontrol_domainbindings(ix)
struct ip_mx *ix;
{
  struct ip_mx outix;
  /* initialize outix first */
  if (!ip_mx_init(&outix)) return -1;

  stralloc outdomain = {0};
  stralloc outsa = {0};
  struct constmap mapsenderips;
  char *senderdomain;
  char *senderip;
  int x;
  /* for IPv4 is control/domainbindings and IPv6 is control/domainbindings6 */
#ifdef INET6
  if (ix->af == AF_INET6) {
    switch(control_readfile(&outsa,"control/domainbindings6",0)) {
      case -1:
        temp_control();
      case 0:
        if (!constmap_init_char(&mapsenderips,"",0,1,'|')) temp_nomem(); break;
      case 1:
        if (!constmap_init_char(&mapsenderips,outsa.s,outsa.len,1,'|')) temp_nomem(); break;
    }
  } else {
    switch(control_readfile(&outsa,"control/domainbindings",0)) {
      case -1:
        temp_control();
      case 0:
        if (!constmap_init_char(&mapsenderips,"",0,1,'|')) temp_nomem(); break;
      case 1:
        if (!constmap_init_char(&mapsenderips,outsa.s,outsa.len,1,'|')) temp_nomem(); break;
    }
  }
#else
  switch(control_readfile(&outsa,"control/domainbindings",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init_char(&mapsenderips,"",0,1,'|')) temp_nomem(); break;
    case 1:
      if (!constmap_init_char(&mapsenderips,outsa.s,outsa.len,1,'|')) temp_nomem(); break;
  }
#endif
  /* we can't use canonhost here since it will be the recipient by now hence we need to use sender.s */
  senderdomain = 0;
  if (sender.len > 0) {
    x = str_rchr(sender.s,'@');
    if (x) {
      senderdomain = sender.s + x + 1;
    }
    stralloc_copyb(&outdomain,senderdomain,sender.len - x - 1);
  }
  senderip = 0;
  if (outdomain.len > 0 && outdomain.s) {
    for (x = 0; x <= outdomain.len; ++x) {
      if ((x == 0) || (x == outdomain.len) || (outdomain.s[x] == '.')) {
        if (senderip = constmap(&mapsenderips,outdomain.s + x,outdomain.len - x)) break;
      }
    }
  }
  if (senderip && !*senderip) senderip = 0;
  if (senderip) {
    int domainbindingipok = 0;
#ifdef INET6
    if (ix->af == AF_INET6) {
      /* check for ':' colon character for simple IPv6 address */
      if (byte_chr(senderip,str_len(senderip),':') == str_len(senderip)) temp_badip6();
      if (!ip6_scan(senderip,&outix.addr.ip6)) temp_badip6();
      //if (!ipme_is46(&outix)) temp_badip6(); /* why this isn't working :( */
      //if (!ipme_is6(&outix.addr.ip6)) temp_badip6(); /* why this isn't working as well :( */
      domainbindingipok = 1;
    } else {
      if (!ip_scan(senderip,&outix.addr.ip)) temp_badip();
      if (!ipme_is(&outix.addr.ip)) temp_badip();
      domainbindingipok = 1;
    }
#else
    if (!ip_scan(senderip,&outix.addr.ip)) temp_badip();
    if (!ipme_is(&outix.addr.ip)) temp_badip();
    domainbindingipok = 1;
#endif
    if (domainbindingipok > 0) {
      outix.af = ix->af;
      x = bind_by_changeoutgoingip(&outix,1);
      if (x == 1) {
        /* set helo name to sender's domain */
        if (!stralloc_copy(&helohost,&outdomain)) temp_nomem();
        constmap_free(&mapsenderips);
      } else {
        constmap_free(&mapsenderips);
      }
      return x;
    }
  }
  constmap_free(&mapsenderips);
  return 0;
}

/* return 1 for success otherwise return 0 */
int getcontrol_helohostbindings(ix)
struct ip_mx *ix;
{
  struct ip_mx outix;
  if (!get_bind_ixlocal(&outix)) return 0;
  if (outix.af != ix->af) return 0;

  stralloc bindsa = {0};
  stralloc helohostname = {0};
  struct constmap maphelohostbind;
  char outipstr[IPFMT];
  int iplen = 0;

  switch(control_readfile(&bindsa,"control/helohostbindings",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init_char(&maphelohostbind,"",0,1,'|')) temp_nomem(); break;
    case 1:
      if (!constmap_init_char(&maphelohostbind,bindsa.s,bindsa.len,1,'|')) temp_nomem(); break;
  }
#ifdef INET6
  if (outix.af == AF_INET6) {
    iplen = ip6_fmt(outipstr,&outix.addr.ip6);
  } else {
    iplen = ip_fmt(outipstr,&outix.addr.ip);
  }
#else
  iplen = ip_fmt(outipstr,&outix.addr.ip);
#endif
  if (iplen > 0) {
    outipstr[iplen] = 0;
    stralloc senderip = {0};
    char *helodomain;
    if (!stralloc_copyb(&senderip, outipstr, iplen)) temp_nomem();
    stralloc_0(&senderip);
    senderip.len--;
    helodomain = 0;
    helodomain = constmap(&maphelohostbind,senderip.s,senderip.len);
    if (helodomain && !*helodomain) helodomain = 0; /* no match */
    if (helodomain) { /* match */
      /* copy the helodomain into helohostname */
      if (!stralloc_copys(&helohostname, helodomain)) temp_nomem();
      if (!str_equal(helohost.s, helodomain)) {
        /* set helo name to helohostname */
        if (!stralloc_copy(&helohost, &helohostname)) temp_nomem();
        constmap_free(&maphelohostbind);
        return 1;
      }
    }
  }
  constmap_free(&maphelohostbind);
  return 0;
}

void getcontrols()
{
  if (control_init() == -1) temp_control();
  if (control_readint(&timeout,"control/timeoutremote") == -1) temp_control();
  if (control_readint(&timeoutconnect,"control/timeoutconnect") == -1)
    temp_control();
  if (control_rldef(&helohost,"control/helohost",1,(char *) 0) != 1)
    temp_control();
  switch(control_readfile(&routes,"control/smtproutes",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&maproutes,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&maproutes,routes.s,routes.len,1)) temp_nomem(); break;
  }
}

int timeoutconn46(fd, ix, port, timeout)
int fd;
struct ip_mx *ix;
int port;
int timeout;
{
#ifdef INET6
  if (ix->af == AF_INET6)
    return timeoutconn6(fd, &ix->addr.ip6, port, timeout);
#endif
  return timeoutconn(fd, &ix->addr.ip, port, timeout);
}

void main(argc,argv)
int argc;
char **argv;
{
  static ipalloc ip = {0};
  int i;
  int r;
  unsigned long random;
  char **recips;
  unsigned long prefme;
  int flagallaliases;
  int flagalias;
  char *relayhost;

  sig_pipeignore();
  if (argc < 4) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();


  if (!stralloc_copys(&host,argv[1])) temp_nomem();

  relayhost = 0;
  for (i = 0;i <= host.len;++i)
    if ((i == 0) || (i == host.len) || (host.s[i] == '.'))
      if (relayhost = constmap(&maproutes,host.s + i,host.len - i))
        break;
  if (relayhost && !*relayhost) relayhost = 0;

  if (relayhost) {
    i = str_chr(relayhost,':');
    if (relayhost[i]) {
      scan_ulong(relayhost + i + 1,&port);
      relayhost[i] = 0;
    }
    if (!stralloc_copys(&host,relayhost)) temp_nomem();
  }


  addrmangle(&sender,argv[2],&flagalias,0);

  if (!saa_readyplus(&reciplist,0)) temp_nomem();
  if (ipme_init() != 1) temp_oserr();

  flagallaliases = 1;
  recips = argv + 3;
  while (*recips) {
    if (!saa_readyplus(&reciplist,1)) temp_nomem();
    reciplist.sa[reciplist.len] = sauninit;
    addrmangle(reciplist.sa + reciplist.len,*recips,&flagalias,!relayhost);
    if (!flagalias) flagallaliases = 0;
    ++reciplist.len;
    ++recips;
  }


  random = now() + (getpid() << 16);
  switch (relayhost ? dns_ip(&ip,&host) : dns_mxip(&ip,&host,random)) {
    case DNS_MEM: temp_nomem();
    case DNS_SOFT: temp_dns();
    case DNS_HARD: perm_dns();
    case 1:
      if (ip.len <= 0) temp_dns();
  }

  if (ip.len <= 0) perm_nomx();

  prefme = 100000;
  for (i = 0;i < ip.len;++i)
#ifdef INET6
   if (ipme_is46(&ip.ix[i]))
#else
   if (ipme_is(&ip.ix[i].addr.ip))
#endif
      if (ip.ix[i].pref < prefme)
        prefme = ip.ix[i].pref;

  if (relayhost) prefme = 300000;
  if (flagallaliases) prefme = 500000;

  for (i = 0;i < ip.len;++i)
    if (ip.ix[i].pref < prefme)
      break;

  if (i >= ip.len)
    perm_ambigmx();

  for (i = 0;i < ip.len;++i) if (ip.ix[i].pref < prefme) {
    if (tcpto(&ip.ix[i])) continue;

    smtpfd = socket(ip.ix[i].af,SOCK_STREAM,0);
    if (smtpfd == -1) temp_oserr();

    /* for domainbindings */
    r = getcontrol_domainbindings(&ip.ix[i]);
    if (r == -1) temp_nobind1();
    if (r == -2) temp_nobind2();

    /* for bindroutes */
    r = bind_by_bindroutes(&ip.ix[i], 0);
    if (r == -1) temp_nobind1();
    if (r == -2) temp_nobind2();

    /* for outgoingip/outgoingip6 */
    r = getcontrol_outgoingip(&ip.ix[i]);
    if (r == -1) temp_nobind1();
    if (r == -2) temp_nobind2();

    /* for helohostbindings */
    getcontrol_helohostbindings(&ip.ix[i]);

    if (timeoutconn46(smtpfd,&ip.ix[i],(unsigned int) port,timeoutconnect) == 0) {
      tcpto_err(&ip.ix[i],0);
      partner = ip.ix[i];
      smtp(); /* does not return */
    }
    tcpto_err(&ip.ix[i],errno == error_timeout
#ifdef TCPTO_REFUSED
			|| errno == error_refused
#endif
    );
    close(smtpfd);
  }
  
  temp_noconn();
}
