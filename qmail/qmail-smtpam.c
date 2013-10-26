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

stralloc helohost = {0};
stralloc routes = {0};
struct constmap maproutes;
stralloc host = {0};
stralloc sender = {0};
stralloc recipient = {0};

struct ip_mx partner;

void out(s) char *s; { if (substdio_puts(subfdoutsmall,s) == -1) _exit(111); }
void zero() { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(111); }
void zerodie() { zero(); substdio_flush(subfdoutsmall); _exit(111); }
void outsafe(sa) stralloc *sa; { int i; char ch;
for (i = 0;i < sa->len;++i) {
ch = sa->s[i]; if (ch < 33) ch = '?'; if (ch > 126) ch = '?';
if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(111); } }

void temp_nomem() { out("421 Out of memory. (#4.3.0)\n"); zerodie(); }
void temp_oserr() { out("421 System resources temporarily unavailable. (#4.3.0)\n"); zerodie(); }
void temp_noconn() { out("421 Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)\n"); zerodie(); }
void temp_read() { out("421 Unable to read message. (#4.3.0)\n"); zerodie(); }
void temp_dnscanon() { out("421 CNAME lookup failed temporarily. (#4.4.3)\n"); zerodie(); }
void temp_dns() { out("421 Sorry, I couldn't find any host by that name. (#4.1.2)\n"); zerodie(); }
void temp_chdir() { out("421 Unable to switch to home directory. (#4.3.0)\n"); zerodie(); }
void temp_control() { out("421 Unable to read control files. (#4.3.0)\n"); zerodie(); }
void perm_usage() { out("421 I (qmail-smtpam) was invoked improperly. (#5.3.5)\n"); zerodie(); }
void perm_dns() { out("421 Sorry, I couldn't find any host named ");
outsafe(&host);
out(". (#5.1.2)\n"); zerodie(); }
void perm_nomx() { out("421 Sorry, I couldn't find a mail exchanger or IP address. (#5.4.4)\n");
zerodie(); }
void perm_ambigmx() { out("421 Sorry. Although I'm listed as a best-preference MX or A for that host,\n\
it isn't in my control/locals file, so I don't treat it as local. (#5.4.6)\n");
zerodie(); }

void outhost()
{
  char x[IPFMT];
  if (substdio_put(subfdoutsmall,x,ip_fmt(x,&partner)) == -1) _exit(111);
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
    if (substdio_put(subfdoutsmall,smtptext.s,smtptext.len) == -1) _exit(111);
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
      if (r == 0) temp_read();
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
 
  if (smtpcode() != 220) quit("ZConnected to "," but greeting failed");
 
  substdio_puts(&smtpto,"HELO ");
  substdio_put(&smtpto,helohost.s,helohost.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 250) quit("ZConnected to "," but my name was rejected");
 
  substdio_puts(&smtpto,"MAIL FROM:<>\r\n");
  substdio_flush(&smtpto);
  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was rejected");
 
  substdio_puts(&smtpto,"RCPT TO:<");
  substdio_put(&smtpto,recipient.s,recipient.len);
  substdio_puts(&smtpto,">\r\n");
  substdio_flush(&smtpto);
  code = smtpcode();
  close(smtpfd);
  if (code == 250) _exit(0);
  _exit(1);
}

void getcontrols()
{
  if (control_init() == -1) temp_control();
  if (control_readint(&timeout,"control/timeoutremote") == -1) temp_control();
  if (control_readint(&timeoutconnect,"control/timeoutconnect") == -1)
    temp_control();
  if (control_rldef(&helohost,"control/helohost",1,(char *) 0) != 1)
    temp_control();
}

char up[513];
int uplen;

int main(argc,argv)
int argc;
char **argv;
{
  static ipalloc ip = {0};
  int i;
  int r;
  unsigned long prefme;
 
  sig_pipeignore();
  if (argc < 2) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();
 
  if (!stralloc_copys(&host,argv[1])) temp_nomem();
  if (argv[2])
    scan_ulong(argv[2],&port);

  if (ipme_init() != 1) temp_oserr();

  uplen = 0;
  for (;;) {
    do
      r = read(3,up + uplen,sizeof(up) - uplen);
    while ((r == -1) && (errno == EINTR));
    if (r == -1) _exit(111);
    if (r == 0) break;
    uplen += r;
    if (uplen >= sizeof(up)) _exit(111);
  }
  close(3);

  if (!stralloc_copys(&recipient,up)) temp_nomem();
  if (!stralloc_0(&recipient)) temp_nomem(); 

  switch (dns_ip(&ip,&host)) {
    case DNS_MEM: temp_nomem(); 
    case DNS_SOFT: temp_dns();
    case DNS_HARD: perm_dns();
    case 1:
      if (ip.len <= 0) temp_dns();
  }
 
  if (ip.len <= 0) perm_nomx();
 
  for (i = 0;i < ip.len;++i)
    if (ip.ix[i].pref < prefme)
      break;
 
  if (i >= ip.len)
    perm_ambigmx();
 
  for (i = 0;i < ip.len;++i) if (ip.ix[i].pref < prefme) {
    if (tcpto(&ip.ix[i])) continue;
 
    smtpfd = socket(ip.ix[i].af,SOCK_STREAM,0);
    if (smtpfd == -1) temp_oserr();

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
    tcpto_err(&ip.ix[i],errno == error_timeout);
    close(smtpfd);
  }
  
  temp_noconn();
}
