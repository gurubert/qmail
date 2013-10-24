#include <sys/types.h>
#include <sys/stat.h>
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
#include "fmt.h"
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
#include "base64.h"
#include "ucspitls.h" 
#include "tls_remote.h"

#define HUGESMTPTEXT 5000
#define PORT_SMTP 25  /* silly rabbit, /etc/services is for users */
#define PORT_QMTP 209 
unsigned long port = PORT_SMTP;

#define PORT_SMTPS 465
#define VERIFYDEPTH 1

int flagtls = 0;	/* -1 = not ; 0 = no, default ; 1 = TLS ; 2 = TLS + Cert ; 3 = TLS + verify ; 4 = TLS + verify + valid; +10 = SMTPS */
int flagtlsdomain = 0;	/* 0 = no ; 1 = yes ; 2 = cert */

stralloc cafile = {0};
stralloc cadir = {0};
stralloc certfile = {0};
stralloc keyfile = {0};
stralloc keypwd = {0};
stralloc ciphers = {0};
stralloc tlsdest = {0};
stralloc tlsport = {0};
stralloc tlsverf = {0};

SSL *ssl;
SSL_CTX *ctx; 

GEN_ALLOC_typedef(saa,stralloc,sa,len,a)
GEN_ALLOC_readyplus(saa,stralloc,sa,len,a,i,n,x,10,saa_readyplus)
static stralloc sauninit = {0};

stralloc helohost = {0};
stralloc routes = {0};
struct constmap maproutes;
stralloc host = {0};
stralloc sender = {0};
stralloc bounce = {0};
stralloc canonhost = {0};
stralloc canonbox = {0};
stralloc senddomain = {0};

/* Outgoing IP patch: Ideas taken from Alberto Brealey Guzmain (tx) */ 

stralloc domainips = {0};
struct constmap mapdomainips;
char domainip[4];

int flagauth = 0;		/* login = 1; plain = 2; crammd5 = 3 */
stralloc authsenders = {0};
struct constmap mapauthsenders;
stralloc user = {0};
stralloc pass = {0};
stralloc auth = {0};
stralloc chal  = {0};
stralloc slop  = {0};
stralloc plain = {0};
char *authsender;

stralloc qmtproutes = {0};
struct constmap mapqmtproutes;

saa reciplist = {0};

struct ip_mx partner;

void out(s) char *s; { if (substdio_puts(subfdoutsmall,s) == -1) _exit(0); }
void zero() { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(0); }
void zerodie() {
  zero();
  substdio_flush(subfdoutsmall);
  if (ssl) tls_exit(ssl);
  _exit(0);
}

void outsafe(sa) stralloc *sa; { int i; char ch;
for (i = 0;i < sa->len;++i) {
ch = sa->s[i]; if (ch < 33) ch = '?'; if (ch > 126) ch = '?';
if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(0); } }

<<<<<<< HEAD
void temp_noip() { out("Zinvalid ipaddr in control/domainips (#4.3.0)\n"); zerodie(); }
=======
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
>>>>>>> ipv6
void temp_nomem() { out("ZOut of memory. (#4.3.0)\n"); zerodie(); }
void temp_oserr() { out("Z\
System resources temporarily unavailable. (#4.3.0)\n"); zerodie(); }
void temp_noconn() { out("Z\
Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)\n"); zerodie(); }
void temp_qmtpnoc() { out("Z\
Sorry, I wasn't able to establish an QMTP connection. (#4.4.1)\n"); zerodie(); }
void temp_read() { out("ZUnable to read message. (#4.3.0)\n"); zerodie(); }
void temp_dnscanon() { out("Z\
CNAME lookup failed temporarily for: "); outsafe(&canonhost); out(". (#4.4.3)\n"); zerodie(); }
void temp_dns() { out("Z\
Sorry, I couldn't find any host named: "); outsafe(&host); out(". (#4.1.2)\n"); zerodie(); }
void temp_chdir() { out("Z\
Unable to switch to home directory. (#4.3.0)\n"); zerodie(); }
void temp_control() { out("Z\
Unable to read control files. (#4.3.0)\n"); zerodie(); }
void perm_partialline() { out("D\
SMTP cannot transfer messages with partial final lines. (#5.6.2)\n"); zerodie(); }
void temp_proto() { out("Z\
recipient did not talk proper QMTP (#4.3.0)\n"); zerodie(); }
void perm_usage() { out("D\
I (qmail-remote) was invoked improperly. (#5.3.5)\n"); zerodie(); }
void perm_dns() { out("D\
Sorry, I couldn't find any host named "); outsafe(&host); out(". (#5.1.2)\n"); zerodie(); }
void perm_nomx() { out("D\
Sorry, I couldn't find a mail exchanger or IP address. (#5.4.4)\n"); zerodie(); }
void perm_ambigmx() { out("D\
Sorry. Although I'm listed as a best-preference MX or A for that host,\n\
it isn't in my control/locals file, so I don't treat it as local. (#5.4.6)\n");
zerodie(); }

void temp_tlscert() { out("Z\
Can't load X.509 certificate: "); outsafe(&certfile); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlskey() { out("Z\
Can't load X.509 private key: "); outsafe(&keyfile); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlschk() { out("Z\
Keyfile does not match X.509 certificate: "); outsafe(&keypwd); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlsctx() { out("Z\
I wasn't able to create TLS context. (#4.4.1)\n"); zerodie(); }
void temp_tlscipher() { out("Z\
I wasn't able to process the TLS ciphers: "); outsafe(&ciphers); out (" (#4.4.1)\n"); zerodie(); }
void temp_tlsca() { out("Z\
I wasn't able to set up CAFILE: "); outsafe(&cafile); out(" or CADIR: "); 
outsafe(&cadir); out(" for TLS. (#4.4.1)\n"); zerodie(); }
void temp_tlspeercert() { out("Z\
Unable to obtain X.500 certificate from: "); outsafe(&host); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlspeervalid() { out("Z\
Unable to validate X.500 certificate Subject for: "); outsafe(&host); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlspeerverify() { out("Z\
Unable to verify X.500 certificate from: "); outsafe(&host); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlscon() { out("Z\
I wasn't able to establish a TLS connection with: "); outsafe(&host); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlserr() { out("Z\
Unknown TLS error for host: "); outsafe(&host); out(". (#4.4.1)\n"); zerodie(); }
void temp_tlsexit() { out("Z\
I wasn't able to gracefully close the TLS connection with: "); outsafe(&host); out(". (#4.4.1)\n"); zerodie(); }

void err_authprot() {
  out("Kno supported AUTH method found, continuing without authentication.\n");
  zero();
  substdio_flush(subfdoutsmall);
}

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
  if (ssl) {
    r = tls_timeoutread(timeout,smtpfd,smtpfd,ssl,buf,len);
    if (r < 0) temp_tlserr();
  } else
  r = timeoutread(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}
int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  if (ssl) {
    r = tls_timeoutwrite(timeout,smtpfd,smtpfd,ssl,buf,len);
    if (r < 0) temp_tlserr();
  } else
  r = timeoutwrite(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}


char inbuf[1450];
substdio ssin = SUBSTDIO_FDBUF(read,0,inbuf,sizeof inbuf);
char smtptobuf[1450];
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
  int i;
  int o;
  char in[4096];
  char out[4096*2+1];
  int sol;

  for (sol = 1;;) {
    r = substdio_get(&ssin,in,sizeof in);
    if (r == 0) break;
    if (r == -1) temp_read();

    for (i = o = 0; i < r; ) {
      if (sol && in[i] == '.') {
	out[o++] = '.';
	out[o++] = in[i++];
      }
      sol = 0;
      while (i < r) {
	if (in[i] == '\n') {
	  sol = 1;
	  ++i;
	  out[o++] = '\r';
	  out[o++] = '\n';
	  break;
	}
	out[o++] = in[i++];
      }
    }
    substdio_put(&smtpto,out,o);
  }
 
  if (!sol) perm_partialline();
  flagcritical = 1;
  substdio_put(&smtpto,".\r\n",3);
  substdio_flush(&smtpto);
}

stralloc recip = {0};

void mailfrom()
{
  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,">\r\n");
  substdio_flush(&smtpto);
}

/* this file is too long -------------------------------------- client TLS */

stralloc domaincerts = {0};
struct constmap mapdomaincerts;
stralloc tlsdestinations = {0};
struct constmap maptlsdestinations;

char *partner_fqdn = 0;
char *tlsdestinfo = 0;
char *tlsdomaininfo = 0;
unsigned long verifydepth = VERIFYDEPTH;

void tls_init()
{
/* Client CTX */

  ctx = ssl_client();
  ssl_errstr();
  if (!ctx) temp_tlsctx();

/* Fetch CA infos for dest */

  if (cafile.len || cadir.len) 
    if (!ssl_ca(ctx,cafile.s,cadir.s,(int) verifydepth)) temp_tlsca();

  if (ciphers.len)
    if (!ssl_ciphers(ctx,ciphers.s)) temp_tlscipher();

/* Prepare for Certificate Request */

  if (flagtlsdomain == 2) {
    switch(tls_certkey(ctx,certfile.s,keyfile.s,keypwd.s)) {
      case  0: break;
      case -1: temp_tlscert();
      case -2: temp_tlskey();
      case -3: temp_tlschk();
    }
  }

/* Set SSL Context */

  ssl = ssl_new(ctx,smtpfd);
  if (!ssl) temp_tlsctx();

/* Setup SSL FDs */
 
  if(!tls_conn(ssl,smtpfd)) temp_tlscon(); 

/* Go on in none-blocking mode */

  if (tls_timeoutconn(timeout,smtpfd,smtpfd,ssl) <= 0)
    temp_tlserr();
}

int starttls_peer()
{
  int i = 0;

  while ( (i += str_chr(smtptext.s+i,'\n') + 1) && 
          (i+8 < smtptext.len) ) {
          if (!str_diffn(smtptext.s+i+4,"STARTTLS",8)) return 1; }

  return 0;
}

void tls_peercheck()
{
  switch(tls_checkpeer(ssl,host.s,host.len,flagtls)) {
    case -1: temp_tlspeercert();
    case -2: temp_tlspeerverify();
    case -3: temp_tlspeervalid();
  }
  flagtls = 100;
}
  
/* this file is too long -------------------------------------- client auth */

stralloc xuser = {0};

int xtext(sa,s,len)
stralloc *sa;
char *s;
int len;
{
  int i;

  if(!stralloc_copys(sa,"")) temp_nomem();

  for (i = 0; i < len; i++) {
    if (s[i] == '=') {
      if (!stralloc_cats(sa,"+3D")) temp_nomem();
    } else if (s[i] == '+') {
        if (!stralloc_cats(sa,"+2B")) temp_nomem();
    } else if ((int) s[i] < 33 || (int) s[i] > 126) {
        if (!stralloc_cats(sa,"+3F")) temp_nomem(); /* ok. not correct */
    } else if (!stralloc_catb(sa,s+i,1)) {
        temp_nomem();
    }
  }

  return sa->len;
}

void mailfrom_xtext()
{
  if (!xtext(&xuser,user.s,user.len)) temp_nomem();
  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,"> AUTH=");
  substdio_put(&smtpto,xuser.s,xuser.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
}
  
int mailfrom_plain()
{
  substdio_puts(&smtpto,"AUTH PLAIN\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (AUTH PLAIN).");

  if(!stralloc_cat(&plain,&sender)) temp_nomem(); /* Mail From: <authorize-id> */
  if(!stralloc_0(&plain)) temp_nomem();
  if(!stralloc_cat(&plain,&user)) temp_nomem(); /* user-id */
  if(!stralloc_0(&plain)) temp_nomem();
  if(!stralloc_cat(&plain,&pass)) temp_nomem(); /* password */
  if (b64encode(&plain,&auth)) quit("ZConnected to "," but unable to base64encode (plain).");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 235) { mailfrom_xtext(); return 0; }
  else if (smtpcode() == 534)  return -1;
  else { quit("ZConnected to "," but authentication was rejected (plain)."); return 1; }
 
  return 0;
}

int mailfrom_login()
{
  substdio_puts(&smtpto,"AUTH LOGIN\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (AUTH LOGIN).");

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&user,&auth)) quit("ZConnected to "," but unable to base64encode user.");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (username).");

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&pass,&auth)) quit("ZConnected to "," but unable to base64encode pass.");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 235) { mailfrom_xtext(); return 0; }
  else if (smtpcode() == 534)  return -1;
  else { quit("ZConnected to "," but authentication was rejected (login)."); return 1; }
 
  return 0;
}

int mailfrom_cram()
{
  int j;
  unsigned char digest[16];
  unsigned char digascii[33];
  static char hextab[]="0123456789abcdef";

  substdio_puts(&smtpto,"AUTH CRAM-MD5\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (AUTH CRAM-MD5).");

  if (str_chr(smtptext.s+4,' ')) {                      /* Challenge */
    if(!stralloc_copys(&slop,"")) temp_nomem();
    if (!stralloc_copyb(&slop,smtptext.s+4,smtptext.len-5)) temp_nomem();
    if (b64decode(slop.s,slop.len,&chal)) quit("ZConnected to "," but unable to base64decode challenge.");
  }

  hmac_md5(chal.s,chal.len,pass.s,pass.len,digest);

  for (j = 0;j < 16;j++)                                /* HEX => ASCII */
  {
    digascii[2*j] = hextab[digest[j] >> 4];
    digascii[2*j+1] = hextab[digest[j] & 0xf];
  }
  digascii[32]=0;

  slop.len = 0;
  if (!stralloc_copys(&slop,"")) temp_nomem();
  if (!stralloc_cat(&slop,&user)) temp_nomem();          /* user-id */
  if (!stralloc_cats(&slop," ")) temp_nomem();
  if (!stralloc_catb(&slop,digascii,32)) temp_nomem();   /* digest */

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&slop,&auth)) quit("ZConnected to "," but unable to base64encode username+digest.");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 235) { mailfrom_xtext(); return 0; }
  else if (smtpcode() == 534)  return -1;
  else { quit("ZConnected to "," but authentication was rejected (cram-md5)."); return 1; }
 
  return 0;
}

void smtp_auth()
{
  int i, j;

  for (i = 0; i + 8 < smtptext.len; i += str_chr(smtptext.s+i,'\n')+1)
    if (!str_diffn(smtptext.s+i+4,"AUTH",4)) {
      if (j = str_chr(smtptext.s+i+8,'C') > 0)          /* AUTH CRAM-MD5 */
        if (case_starts(smtptext.s+i+8+j,"CRAM"))
          if (mailfrom_cram() >= 0) return;

      if (j = str_chr(smtptext.s+i+8,'L') > 0)          /* AUTH LOGIN */
        if (case_starts(smtptext.s+i+8+j,"LOGIN"))
          if (mailfrom_login() >= 0) return;

      if (j = str_chr(smtptext.s+i+8,'P') > 0)          /* AUTH PLAIN */
        if (case_starts(smtptext.s+i+8+j,"PLAIN"))
          if (mailfrom_plain() >= 0) return;

      err_authprot();
      mailfrom();
    }
}

/* this file is too long -------------------------------------- smtp client */

unsigned long code;

void smtp_greeting()
{
  substdio_puts(&smtpto,"EHLO ");
  substdio_put(&smtpto,helohost.s,helohost.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);

  if (smtpcode() != 250) {
    substdio_puts(&smtpto,"HELO ");
    substdio_put(&smtpto,helohost.s,helohost.len);
    substdio_puts(&smtpto,"\r\n");
    substdio_flush(&smtpto);
    code = smtpcode();
    authsender = 0;
    if (code >= 500) quit("DConnected to "," but my name was rejected");
    if (code != 250) quit("ZConnected to "," but my name was rejected");
  }
}

void smtp_starttls()
{
  substdio_puts(&smtpto,"STARTTLS\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 220) {
    tls_init();
    tls_peercheck();
    smtp_greeting();
  }
  else {
    flagtls = -2;
    quit("ZConnected to "," but STARTTLS was rejected.");
  }
}

void smtp()
{
  int flagbother;
  int i;

  if (flagtls > 10 && flagtls < 100) {          /* SMTPS */
    tls_init();
    tls_peercheck(); 
  }

  code = smtpcode();
  if (code == 421) quit("ZConnected to "," but greylisted");
  if (code != 220) quit("ZConnected to "," but greeting failed");

  smtp_greeting();

  if (flagtls > 0 && flagtls < 10)              /* STARTTLS */
    if (starttls_peer()) smtp_starttls();

  if (user.len && pass.len)			/* AUTH */
    smtp_auth();
  else 
    mailfrom();

  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was greylisted");
 
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
  if (code == 451) quit("Z"," message was greylisted");
  if (code >= 400) quit("Z"," failed on DATA command");
 
  blast();
  code = smtpcode();
  flagcritical = 0;
  if (code >= 500) quit("D"," failed after I sent the message");
  if (code >= 400) quit("Z"," failed after I sent the message");
  if (flagtls == 100) quit("K"," TLS transmitted message accepted");
  else quit("K"," accepted message");
}

/* this file is too long -------------------------------------- qmtp client */

int qmtpsend = 0;

void qmtp()
{
  struct stat st;
  unsigned long len;
  char *x;
  int i;
  int n;
  unsigned char ch;
  char num[FMT_ULONG];
  int flagallok;

  if (fstat(0,&st) == -1) quit("Z", " unable to fstat stdin");
  len = st.st_size;

  /* the following code was substantially taken from serialmail'ss serialqmtp.c */
  substdio_put(&smtpto,num,fmt_ulong(num,len+1));
  substdio_put(&smtpto,":\n",2);
  while (len > 0) {
    n = substdio_feed(&ssin);
    if (n <= 0) _exit(32); /* wise guy again */
    x = substdio_PEEK(&ssin);
    substdio_put(&smtpto,x,n);
    substdio_SEEK(&ssin,n);
    len -= n;
  }
  substdio_put(&smtpto,",",1);

  len = sender.len;
  substdio_put(&smtpto,num,fmt_ulong(num,len));
  substdio_put(&smtpto,":",1);
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_put(&smtpto,",",1);

  len = 0;
  for (i = 0;i < reciplist.len;++i)
    len += fmt_ulong(num,reciplist.sa[i].len) + 1 + reciplist.sa[i].len + 1;
  substdio_put(&smtpto,num,fmt_ulong(num,len));
  substdio_put(&smtpto,":",1);
  for (i = 0;i < reciplist.len;++i) {
    substdio_put(&smtpto,num,fmt_ulong(num,reciplist.sa[i].len));
    substdio_put(&smtpto,":",1);
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_put(&smtpto,",",1);
  }
  substdio_put(&smtpto,",",1);
  substdio_flush(&smtpto);

  flagallok = 1;

  for (i = 0;i < reciplist.len;++i) {
    len = 0;
    for (;;) {
      get(&ch);
      if (ch == ':') break;
      if (len > 200000000) temp_proto();
      if (ch - '0' > 9) temp_proto();
      len = 10 * len + (ch - '0');
    }
    if (!len) temp_proto();
    get(&ch); --len;
    if ((ch != 'Z') && (ch != 'D') && (ch != 'K')) temp_proto();

    if (!stralloc_copyb(&smtptext,&ch,1)) temp_proto();
    if (!stralloc_cats(&smtptext,"qmtp: ")) temp_nomem();

    while (len > 0) {
      get(&ch);
      --len;
    }

    for (len = 0;len < smtptext.len;++len) {
      ch = smtptext.s[len];
      if ((ch < 32) || (ch > 126)) smtptext.s[len] = '?';
    }
    get(&ch);
    if (ch != ',') temp_proto();
    smtptext.s[smtptext.len-1] = '\n';

    if (smtptext.s[0] == 'K') out("r");
    else if (smtptext.s[0] == 'D') {
      out("h");
      flagallok = 0;
    }
    else { /* if (smtptext.s[0] == 'Z') */
      out("s");
      flagallok = 0;
    }
    if (substdio_put(subfdoutsmall,smtptext.s+1,smtptext.len-1) == -1) temp_qmtpnoc();
    zero();
  }
  if (!flagallok) {
    out("DGiving up on ");outhost();out("\n");
  } else {
    out("KAll received okay by ");outhost();out("\n");
  }
  zerodie();
}

/* this file is too long -------------------------------------- common */

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
  switch(control_readfile(&domainips,"control/domainips",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapdomainips,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapdomainips,domainips.s,domainips.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&authsenders,"control/authsenders",0)) {
    case -1:
       temp_control();
    case 0:
      if (!constmap_init(&mapauthsenders,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapauthsenders,authsenders.s,authsenders.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&qmtproutes,"control/qmtproutes",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapqmtproutes,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapqmtproutes,qmtproutes.s,qmtproutes.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&domaincerts,"control/domaincerts",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapdomaincerts,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapdomaincerts,domaincerts.s,domaincerts.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&tlsdestinations,"control/tlsdestinations",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&maptlsdestinations,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&maptlsdestinations,tlsdestinations.s,tlsdestinations.len,1)) temp_nomem(); break;
  }
}

<<<<<<< HEAD
int main(argc,argv)
=======
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
>>>>>>> ipv6
int argc;
char **argv;
{
  static ipalloc ip = {0};
<<<<<<< HEAD
  struct stat st;
  int i, j, k, m;
=======
  int i;
  int r;
>>>>>>> ipv6
  unsigned long random;
  char **recips;
  unsigned long prefme;
  int flagallaliases;
  int flagalias;
  char *relayhost;
<<<<<<< HEAD
  char *localip;
   
=======

>>>>>>> ipv6
  sig_pipeignore();
  if (argc < 4) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();
<<<<<<< HEAD
 
  if (!stralloc_copys(&host,argv[1])) temp_nomem();

  authsender = 0;
=======


  if (!stralloc_copys(&host,argv[1])) temp_nomem();

>>>>>>> ipv6
  relayhost = 0;

  addrmangle(&sender,argv[2],&flagalias,0);

/* this file is too long -------------------------------------- set domain ip     */

  localip = 0;
  for (i = 0;i <= canonhost.len;++i)
    if ((i == 0) || (i == canonhost.len) || (canonhost.s[i] == '.'))
      if (localip = constmap(&mapdomainips,canonhost.s + i,canonhost.len - i))
       break;
  if (localip && !*localip) localip = 0;

/* this file is too long -------------------------------------- authsender routes */

  for (i = 0;i <= sender.len;++i)
    if ((i == 0) || (i == sender.len) || (sender.s[i] == '.') || (sender.s[i] == '@'))
      if (authsender = constmap(&mapauthsenders,sender.s + i,sender.len - i))
        break;
<<<<<<< HEAD

  if (authsender && !*authsender) authsender = 0;

  if (authsender) {
    i = str_chr(authsender,'|');
    if (authsender[i]) {
      j = str_chr(authsender + i + 1,'|');
      if (authsender[j]) {
        authsender[i] = 0;
        authsender[i + j + 1] = 0;
        if (!stralloc_copys(&user,"")) temp_nomem();
        if (!stralloc_copys(&user,authsender + i + 1)) temp_nomem();
        if (!stralloc_copys(&pass,"")) temp_nomem();
        if (!stralloc_copys(&pass,authsender + i + j + 2)) temp_nomem();
      }
    }
    i = str_chr(authsender,':');
    if (authsender[i]) {
      scan_ulong(authsender + i + 1,&port);
      authsender[i] = 0;
=======
  if (relayhost && !*relayhost) relayhost = 0;

  if (relayhost) {
    i = str_chr(relayhost,':');
    if (relayhost[i]) {
      scan_ulong(relayhost + i + 1,&port);
      relayhost[i] = 0;
>>>>>>> ipv6
    }
    if (!stralloc_copys(&relayhost,authsender)) temp_nomem();
    if (!stralloc_copys(&host,authsender)) temp_nomem();
  }

/* this file is too long -------------------------------------- standard routes */

  if (!authsender) {
    if (sender.len == 0) {                        /* bounce routes */
      if (!stralloc_copys(&bounce,"!@")) temp_nomem();
      if (relayhost = constmap(&mapqmtproutes,bounce.s,2)) {
         qmtpsend = 1; port = PORT_QMTP;
      } else
         relayhost = constmap(&maproutes,bounce.s,2);
    }

    if (relayhost && !*relayhost) relayhost = 0;

    if (!relayhost) {
      for (i = 0;i <= host.len;++i) {		/* qmtproutes */
        if ((i == 0) || (i == host.len) || (host.s[i] == '.'))
          if (relayhost = constmap(&mapqmtproutes,host.s + i,host.len - i)) {
            qmtpsend = 1; port = PORT_QMTP;
            break;
          }					/* default smtproutes */
          else if (relayhost = constmap(&maproutes,host.s + i,host.len - i))
            break;
      }
    }

    if (relayhost && !*relayhost) relayhost = 0;

    if (relayhost) {				/* default smtproutes -- authenticated */
      i = str_chr(relayhost,'|');
      if (relayhost[i]) {
        j = str_chr(relayhost + i + 1,'|');
        if (relayhost[j]) {
          relayhost[i] = 0;
          relayhost[i + j + 1] = 0;
          if (!stralloc_copys(&user,"")) temp_nomem();
          if (!stralloc_copys(&user,relayhost + i + 1)) temp_nomem();
          if (!stralloc_copys(&pass,"")) temp_nomem();
          if (!stralloc_copys(&pass,relayhost + i + j + 2)) temp_nomem();
        }
      }
      i = str_chr(relayhost,':');
      if (relayhost[i]) {
        scan_ulong(relayhost + i + 1,&port);
        relayhost[i] = 0;
      }
      if (!stralloc_copys(&host,relayhost)) temp_nomem();
    }
  }


/* this file is too long -------------------------------------- TLS destinations */

/* Case 1: Skip this destination domain for TLS destinations */

  for (i = 0;i <= host.len;++i) {
    if ((i == 0) || (i == host.len) || (host.s[i] == '.')) {
      if (!stralloc_copys(&tlsdest,"!")) temp_nomem();
      if (!stralloc_catb(&tlsdest,host.s + i,host.len - i)) temp_nomem();
      if (!stralloc_0(&tlsdest)) temp_nomem();
      if (tlsdestinfo = constmap(&maptlsdestinations,tlsdest.s,host.len - i + 1)) {
        flagtls = -1;
        break;
      }
    }
  }
  cafile.len = cadir.len = ciphers.len = k = 0;

/* Case 2: Validate + Verify Cert for Peerhost -- or any */

  if (!flagtls) {
    if (!stralloc_copys(&tlsdest,"=")) temp_nomem();
    if (!stralloc_catb(&tlsdest,host.s,host.len)) temp_nomem();
    if (!stralloc_0(&tlsdest)) temp_nomem();
    if (tlsdestinfo = constmap(&maptlsdestinations,tlsdest.s,tlsdest.len - 1)) 
      flagtls = 4;
  }

  if (!flagtls) {
    if (!stralloc_copys(&tlsdest,"=")) temp_nomem();
    if (!stralloc_cats(&tlsdest,"*")) temp_nomem();
    if (tlsdestinfo = constmap(&maptlsdestinations,tlsdest.s,2)) 
      flagtls = 4;
  }

/* Case 3: Verify Cert for Hosts/Domains or Any */

  if (!flagtls) {
    for (i = 0;i <= host.len;++i) 
      if ((i == 0) || (i == host.len) || (host.s[i] == '.')) {
        if (!stralloc_copys(&tlsdest,"")) temp_nomem();
        if (!stralloc_catb(&tlsdest,host.s + i,host.len - i)) temp_nomem();
        if (!stralloc_0(&tlsdest)) temp_nomem();
        if (tlsdestinfo = constmap(&maptlsdestinations,tlsdest.s,tlsdest.len - 1)) {
          flagtls = 3;
          break;
        }
      }
  }

/* Case 4: Anonymous TLS without Cert */

  if (!flagtls) {
    for (i = 0;i <= host.len;++i)
      if ((i == 0) || (i == host.len) || (host.s[i] == '.')) {
        if (!stralloc_copys(&tlsdest,"-")) temp_nomem();
        if (!stralloc_catb(&tlsdest,host.s + i,host.len - i)) temp_nomem();
        if (!stralloc_0(&tlsdest)) temp_nomem();
        if (tlsdestinfo = constmap(&maptlsdestinations,tlsdest.s,tlsdest.len - 1)) {
          flagtls = 1;
          break;
        }
      }
  }
  if (!flagtls) {
    if (!stralloc_copys(&tlsdest,"-")) temp_nomem();
    if (!stralloc_cats(&tlsdest,"*")) temp_nomem();
    if (tlsdestinfo = constmap(&maptlsdestinations,tlsdest.s,2))
      flagtls = 1;
  }

/* Case 5: Just TLS for Any */

  if (!flagtls) {
    if (!stralloc_copys(&tlsdest,"*")) temp_nomem();
    if (tlsdestinfo = constmap(&maptlsdestinations,tlsdest.s,1)) 
      flagtls = 2;
  }

/* Fetch corresponding TLS infos for destination */

  if (flagtls > 0) { 
    i = str_chr(tlsdestinfo,'|');			/* ca file */
    if (tlsdestinfo[i]) {
      tlsdestinfo[i] = 0;
      j = str_chr(tlsdestinfo+i+1,'|');			/* cipher */
      if (tlsdestinfo[i+j+1] == '|') {
        tlsdestinfo[i+j+1] = 0; 
        m = str_chr(tlsdestinfo+i+j+2,'|');		/* cone domain */
        if (tlsdestinfo[i+j+m+2] == '|') {
          tlsdestinfo[i+j+m+2] = 0; 
          if (str_diffn(tlsdestinfo[i+j+m+3],canonhost.s,canonhost.len)) flagtls = 0;
        }
        k = str_chr(tlsdestinfo+i+j+2,':');		/* verifydepth:port */
	if (tlsdestinfo[i+j+k+2] == ':') {
          tlsdestinfo[i+j+k+2] = 0;
          if (k > 0) scan_ulong(tlsdestinfo+i+j+2,&verifydepth);
          if (!stralloc_copys(&tlsport,tlsdestinfo+i+j+k+3)) temp_nomem();
          scan_ulong(tlsdestinfo+i+j+k+3,&port);
        }
      }
      if (!stralloc_copys(&ciphers,tlsdestinfo+i+1)) temp_nomem();
    } 
    if (!stralloc_copys(&cafile,tlsdestinfo)) temp_nomem();

/* If cafile name ends with '/' consider it as cadir */

    if (cafile.len) {
      if (cafile.s[cafile.len] == '/') {
        cafile.len = 0;
        if (!stralloc_copys(&cadir,tlsdestinfo)) temp_nomem();
        if (!stralloc_0(&cadir)) temp_nomem();
      } else 
        if (!stralloc_0(&cafile)) temp_nomem(); 
    } 
  }

/* Fetch port if not already done and check for SMTPS */

  if (flagtls > 0 && k == 0) {
    cafile.len = 0;
    j = str_rchr(tlsdestinfo,':');
    if (tlsdestinfo[j] == ':') {
      scan_ulong(tlsdestinfo+j+1,&port);
      if (!stralloc_copys(&tlsport,tlsdestinfo+j+1)) temp_nomem();
      if (!stralloc_0(&tlsport)) temp_nomem();
    }
  }
  if (flagtls > 0 && port == PORT_SMTPS) flagtls = flagtls + 10;

/* this file is too long -------------------------------------- Our Certs */

  if (flagtls > 0) {
    if (!stralloc_copy(&senddomain,&canonhost)) temp_nomem();  

/* Per senddomain Cert */

    for (i = 0;i <= senddomain.len;++i)
      if ((i == 0) || (i == senddomain.len) || (senddomain.s[i] == '.')) {
        if (tlsdomaininfo = constmap(&mapdomaincerts,senddomain.s + i,senddomain.len - i)) {
          flagtlsdomain = 1;
          break;
        }
      }

/* Standard Cert (if any) */

    if (!flagtlsdomain) {
      if (!stralloc_copys(&senddomain,"*")) temp_nomem();
      if (tlsdomaininfo = constmap(&mapdomaincerts,senddomain.s,1))
        flagtlsdomain = 1;
    }

    if (flagtlsdomain) {
      i = str_chr(tlsdomaininfo,'|');
      if (tlsdomaininfo[i]) {
        tlsdomaininfo[i] = 0;
        j = str_chr(tlsdomaininfo + i + 1,'|');
        if (tlsdomaininfo[i + j + 1]) {
          tlsdomaininfo[i + j + 1] = 0;
          if (!stralloc_copys(&keypwd,"")) temp_nomem();
          if (!stralloc_copys(&keypwd,tlsdomaininfo + i + j + 2)) temp_nomem();
          if (!stralloc_0(&keypwd)) temp_nomem();
        }
        if (!stralloc_copys(&keyfile,tlsdomaininfo + i + 1)) temp_nomem();
        if (!stralloc_0(&keyfile)) temp_nomem();
      }
      if (!stralloc_copys(&certfile,tlsdomaininfo)) temp_nomem();
      if (!stralloc_0(&certfile)) temp_nomem();
      flagtlsdomain = 2;
    }
  }

/* this file is too long -------------------------------------- work thru reciplist */

<<<<<<< HEAD
=======
  addrmangle(&sender,argv[2],&flagalias,0);

>>>>>>> ipv6
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

<<<<<<< HEAD
    if (localip) {						/* set domain ip */
      if (!ip_scan(localip,&domainip)) temp_noip();
      if (!stralloc_copy(&helohost,&canonhost)) temp_nomem(); 	/* could be in control file */
    
      if (domainip[0] || domainip[1] || domainip[2] || domainip[3]) {
        struct sockaddr_in si;
        si.sin_family=AF_INET;
        si.sin_port=0;
        byte_copy(&si.sin_addr,4,domainip);
        if (bind(smtpfd,(struct sockaddr*)&si,sizeof(si))) temp_oserr();
      }
    }
 
    if (timeoutconn(smtpfd,&ip.ix[i].ip,(unsigned int) port,timeoutconnect) == 0) {
      tcpto_err(&ip.ix[i].ip,0);
      partner = ip.ix[i].ip;
      if (qmtpsend) 
         qmtp(); 
      else 
         smtp(); /* read THOUGHTS; section 6 */
=======
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
>>>>>>> ipv6
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
