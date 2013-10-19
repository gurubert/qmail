#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"
#include "alloc.h"
#include "auto_qmail.h"
#include "control.h"
#include "received.h"
#include "constmap.h"
#include "error.h"
#include "ipme.h"
#include "ip.h"
#include "qmail.h"
#include "str.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "now.h"
#include "exit.h"
#include "rcpthosts.h"
#include "recipients.h"
#include "mfrules.h"
#include "starttls.h"
#include "smtpdlog.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "commands.h"
#include "cdb.h"
#include "dns.h"
#include "wait.h"
#include "open.h"

#define PAM111421
#define AUTHSLEEP 5
#define SMTPSPORT "465"
#define SUBMISSION "587"

#define MIMETYPE_LEN 9
#define LOADER_LEN 5
#define BASE64MESSAGE "content-transfer-encoding: base64"
#define FDLOG 2

#define MAXHOPS 100
unsigned long databytes = 0;
int timeout = 1200;

int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutwrite(timeout,fd,buf,len);
  if (r <= 0) _exit(1);
  return r;
}

char ssoutbuf[512];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

void flush() { substdio_flush(&ssout); }
void out(s) char *s; { substdio_puts(&ssout,s); }

int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  flush();
  r = timeoutread(timeout,fd,buf,len);
  if (r == -1) if (errno == error_timeout) die_alarm();
  if (r <= 0) die_read();
  return r;
}

char ssinbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);
char ssinfo[128];
substdio ssrbl = SUBSTDIO_FDBUF(saferead,0,ssinfo,sizeof ssinfo);

/* this file is too long -------------------------------------- Greeting      */

stralloc greeting = {0};

void smtp_greet(code) char *code;
{
  substdio_puts(&ssout,code);
  substdio_put(&ssout,greeting.s,greeting.len);
}
void smtp_help()
{
  out("214 qmail home page: http://pobox.com/~djb/qmail.html\r\n");
}
void smtp_quit()
{
  smtp_greet("221 "); out("\r\n"); flush(); _exit(0);
}

char *remoteip;
char *remotehost;
char *remoteinfo;
char *local;
char *localport;
char *relayclient;

stralloc protocol = {0};
stralloc helohost = {0};
char *fakehelo; /* pointer into helohost, or 0 */
stralloc tlsinfo = {0};

char *helocheck;
int flagbadhelo;
int flagdnshelo;
int seenhelo = 0;

char *badmailcond;
char *badhelocond;

void dohelo(arg) char *arg; 
{
  if (!stralloc_copys(&helohost,arg)) die_nomem(); 
  if (!stralloc_0(&helohost)) die_nomem(); 
  fakehelo = case_diffs(remotehost,helohost.s) ? helohost.s : 0;
  if (helocheck) {
      if (str_len(helocheck) == 1) {
        switch (*helocheck) {
          case '=': flagbadhelo = bhelocheck(); 
		    if (fakehelo) { flagdnshelo = 1; badhelocond = "="; } break;
	  case 'A': flagbadhelo = bhelocheck(); 
		    if (flagbadhelo == 0) { flagdnshelo = dnsq(helohost.s,"A"); badhelocond = "A"; } break;
	  case 'M': flagbadhelo = bhelocheck(); 
		    if (flagbadhelo == 0) { flagdnshelo = dnsq(helohost.s,"M"); badhelocond = "M"; } break;
          case '.': flagbadhelo = bhelocheck(); 
		    if (!str_len(arg)) flagbadhelo = -2; break;
          case '!': if (!str_len(arg)) flagbadhelo = -2; break;
        }
      } 
      else 
        flagbadhelo = bhelocheck(); 
    if (flagbadhelo == -3) flagbadhelo = 0;  
  }
  if (!env_unset("HELOHOST")) die_read();
  if (!env_put2("HELOHOST",helohost.s)) die_nomem();
}

int liphostok = 0;
stralloc liphost = {0};

int bmfok = 0;
stralloc bmf = {0};
struct constmap mapbmf;

int brtok= 0;
stralloc brt = {0};
struct constmap mapbrt;

int badhelook = 0;
stralloc badhelo = {0};
struct constmap mapbhlo;

static int fdbmt;
int flagmimetype = 0;
char *badmimeinit;

static int fdblt;
int flagloadertype = 0;
char *badloaderinit;

static int fdmav;
int flagmav = 0;
int localmf = 0;
char *localmfcheck;

char *mfdnscheck;
char *qhpsi;
char *base64;

int maxrcptcount = 0;
int flagerrcpts = 0;
int flagnotorious = 0;

int tarpitcount = 0;
int tarpitdelay = 0;

char *auth;
int smtpauth = 0;	/* 0: none 1: login/plain 2: cram 3: login/plain/cram 11: must login/plain 12: must 2  13: must 3 */
int seenauth = 0;

int starttls = 0;	/* 1: STARTTLS; +10 require */
int seenttls = 0;
char *ucspitls;
char *tlsversion;
char *cipher;
char *cipherperm;
char *cipherused;
char *clientdn;

stralloc mailto = {0};
stralloc deliverto = {0};
char *delivermailto;
stralloc rblinfo = {0};
char *rblsmtpd;
char *spf;
stralloc spfinfo = {0};

void setup()
{
  char *x;
  unsigned long u;
  int i;
 
  if (control_init() == -1) die_control();
  if (control_rldef(&greeting,"control/smtpgreeting",1,(char *) 0) != 1)
    die_control();
  liphostok = control_rldef(&liphost,"control/localiphost",1,(char *) 0);
  if (liphostok == -1) die_control();
  if (control_readint(&timeout,"control/timeoutsmtpd") == -1) die_control();
  if (timeout <= 0) timeout = 1;

  if (rcpthosts_init() == -1) die_control();
  if (recipients_init() == -1) die_control();

  bmfok = control_readfile(&bmf,"control/badmailfrom",0);
  if (bmfok == -1) die_control();
  if (bmfok)
    if (!constmap_init(&mapbmf,bmf.s,bmf.len,0)) die_nomem();

  brtok = control_readfile(&brt,"control/badrcptto",0);
  if (brtok == -1) die_control();
  if (brtok)
    if (!constmap_init(&mapbrt,brt.s,brt.len,0)) die_nomem();
 
  if (control_readint(&databytes,"control/databytes") == -1) die_control();
  x = env_get("DATABYTES");
  if (x) { scan_ulong(x,&u); databytes = u; }
  if (!(databytes + 1)) --databytes;

  if (!stralloc_copys(&protocol,"ESMTP")) die_nomem();   /* RFC 3848 */ 
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";
  localport = env_get("TCPLOCALPORT");
  if (!localport) localport = "0";
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCPREMOTEINFO");
  relayclient = env_get("RELAYCLIENT");

  if (!case_diffs(localport,SMTPSPORT)) 
    if (!modssl_info()) die_starttls();

  mfdnscheck = env_get("MFDNSCHECK");
  x = env_get("MAXRECIPIENTS");
  if (x) { scan_ulong(x,&u); maxrcptcount = u; };
  if (!(maxrcptcount + 1)) --maxrcptcount;

  helocheck = env_get("HELOCHECK");
  if (helocheck) {
    badhelook = control_readfile(&badhelo,"control/badhelo",0);
    if (badhelook == -1) die_control();
    if (badhelook)
      if (!constmap_init(&mapbhlo,badhelo.s,badhelo.len,0)) die_nomem();
  }

  x = env_get("TARPITCOUNT");
  if (x) { scan_ulong(x,&u); tarpitcount = u; };
  x = env_get("TARPITDELAY");
  if (x) { scan_ulong(x,&u); tarpitdelay = u; };

  localmfcheck = env_get("LOCALMFCHECK");
  if (localmfcheck) {
    localmf = 1;
    if (str_len(localmfcheck) == 1 && *localmfcheck == '!') {
      localmf = 2;
      fdmav = open_read("control/mailfromrules.cdb");
      if (fdmav == -1 ) localmf = 1;
    } 
    else if (str_len(localmfcheck) == 1 && *localmfcheck == '=') {
      localmf = 3;
    }
  }

  badmimeinit = env_get("BADMIMETYPE");
  if (badmimeinit) {
    if (str_len(badmimeinit) == 1)
      if (*badmimeinit == '!') flagmimetype = 1;
      fdbmt = open_read("control/badmimetypes.cdb");
      if (fdbmt != -1 ) flagmimetype = flagmimetype + 2;
  }

  badloaderinit = env_get("BADLOADERTYPE");
  if (badloaderinit) {
    if (str_len(badloaderinit) == 1) {
      flagloadertype = 1;
      fdblt = open_read("control/badloadertypes.cdb");
      if (fdblt == -1 ) flagloadertype = 0;
    }
  }

  base64 = env_get("BASE64"); 
  qhpsi = env_get("QHPSI");
  auth = env_get("SMTPAUTH");
  if (auth) {
    smtpauth = 1;
    if (!case_diffs(auth,"-")) smtpauth = 0;
    if (!case_diffs(auth,"!")) smtpauth = 11;
    if (case_starts(auth,"cram")) smtpauth = 2;
    if (case_starts(auth,"+cram")) smtpauth = 3;
    if (case_starts(auth,"!cram")) smtpauth = 12;
    if (case_starts(auth,"!+cram")) smtpauth = 12;
  }

  ucspitls = env_get("UCSPITLS");
  if (ucspitls) {
    starttls = 1;
    if (!case_diffs(ucspitls,"-")) starttls = 0;
    if (!case_diffs(ucspitls,"!")) starttls = 11;
  } 
	
  delivermailto = env_get("DELIVERTO");
  if (delivermailto) {
    if (!stralloc_cats(&mailto,delivermailto)) die_nomem();
    if (!stralloc_cats(&mailto," ")) die_nomem();
  }

  rblsmtpd = env_get("RBLSMTPD");
  if (rblsmtpd) {
    if (!stralloc_cats(&rblinfo,rblsmtpd)) die_nomem();
    if (!stralloc_0(&rblinfo)) die_nomem();
  }

  spf = env_get("SPFINFO");
  if (spf) {
    if (!stralloc_cats(&spfinfo,spf)) die_nomem();
    if (!stralloc_0(&spfinfo)) die_nomem();
  } 
  
  if (!stralloc_copys(&helohost,"")) die_nomem();    /* helohost is empty */ 
  if (!stralloc_0(&helohost)) die_nomem();
  fakehelo = 0;
}

int modssl_info()
{
  tlsversion = env_get("SSL_PROTOCOL");
  if (!tlsversion) return 0;

  cipher = env_get("SSL_CIPHER");
  if (!cipher) cipher = "unknown";
  cipherperm = env_get("SSL_CIPHER_ALGKEYSIZE");
  if (!cipherperm) cipherperm = "unknown";
  cipherused = env_get("SSL_CIPHER_USEKEYSIZE");
  if (!cipherused) cipherused = "unknown";
  clientdn = env_get("SSL_CLIENT_S_DN");
  if (!clientdn) clientdn = "none";

  if (!stralloc_copys(&tlsinfo,tlsversion)) die_nomem();
  if (!stralloc_cats(&tlsinfo,": ")) die_nomem();
  if (!stralloc_cats(&tlsinfo,cipher)) die_nomem();
  if (!stralloc_cats(&tlsinfo," [")) die_nomem();
  if (!stralloc_cats(&tlsinfo,cipherused)) die_nomem();
  if (!stralloc_cats(&tlsinfo,"/")) die_nomem();
  if (!stralloc_cats(&tlsinfo,cipherperm)) die_nomem();
  if (!stralloc_cats(&tlsinfo,"] ")) die_nomem();
  if (!stralloc_cats(&tlsinfo,"DN=")) die_nomem();
  if (!stralloc_cats(&tlsinfo,clientdn)) die_nomem();
  if (!stralloc_0(&tlsinfo)) die_nomem();
  if (!stralloc_cats(&protocol,"S")) die_nomem();
  
  smtp_logt("Accept::TLS::","ESMTPS",remoteip,remotehost,clientdn,cipher);

  return 1;
}

/* this file is too long -------------------------------------- SMTP ADDRESSES */

stralloc addr = {0}; /* will be 0-terminated, if addrparse returns 1 */
stralloc eddr = {0}; /* extended address; used for smart address recognition */
stralloc rddr = {0}; /* test anti-spoofing host name */
stralloc sa = {0};
ipalloc ia = {0};

int addrparse(arg)
char *arg;
{
  int i;
  char ch;
  char terminator;
  struct ip_address ip;
  int flagesc;
  int flagquoted;
 
  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else
    return 0;

  /* strip source route */
  if (*arg == '@') while (*arg) if (*arg++ == ':') break;

  if (!stralloc_copys(&addr,"")) die_nomem();
  flagesc = 0;
  flagquoted = 0;
  for (i = 0;ch = arg[i];++i) { /* copy arg to addr, stripping quotes */
    if (flagesc) {
      if (!stralloc_append(&addr,&ch)) die_nomem();
      flagesc = 0;
    }
    else {
      if (!flagquoted && (ch == terminator)) break;
      switch(ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: if (!stralloc_append(&addr,&ch)) die_nomem();
      }
    }
  }
  /* could check for termination failure here, but why bother? */
  if (!stralloc_append(&addr,"")) die_nomem();

  if (liphostok) {
    i = byte_rchr(addr.s,addr.len,'@');
    if (i < addr.len) /* if not, partner should go read rfc 821 */
      if (addr.s[i + 1] == '[')
        if (!addr.s[i + 1 + ip_scanbracket(addr.s + i + 1,&ip)])
          if (ipme_is(&ip)) {
            addr.len = i + 1;
            if (!stralloc_cat(&addr,&liphost)) die_nomem();
            if (!stralloc_0(&addr)) die_nomem();
          }
  }

  if (addr.len > 900) return 0;
  return 1;
}

int bmfcheck()
{
  int i = 0;
  int j = 0;
  int k = 0; 
  int dlen;
  char subvalue;

  if (bmfok) {
    int rlen = str_len(remotehost);
    int at = byte_rchr(addr.s,addr.len,'@');
    if (at >= addr.len) at = 0;

/* '?' enhanced address to skip all other tests including MFDNSCHECK */

    eddr.len = 0;
    if (!stralloc_copys(&eddr,"?")) die_nomem();
    if (!stralloc_cat(&eddr,&addr)) die_nomem();
    case_lowerb(eddr.s,eddr.len);
    if (constmap(&mapbmf,eddr.s,eddr.len - 1)) return -111;

/* '+' extended address for none-RELAYCLIENTS */

    if (at && !relayclient) {
      eddr.len = 0;
      if (!stralloc_copyb(&eddr,addr.s,addr.len - 1)) die_nomem();
      if (!stralloc_append(&eddr,"+")) die_nomem();
      if (!stralloc_0(&eddr)) die_nomem();
      case_lowerb(eddr.s,eddr.len);
      if (constmap(&mapbmf,eddr.s + at,eddr.len - at - 1)) return -5;
    }

/* '-' extended address from UNKNOWN */

    if (j && !case_diffs(remotehost,"unknown")) {
      eddr.len = 0;
      if (!stralloc_copyb(&eddr,addr.s,addr.len - 1)) die_nomem();
      if (!stralloc_append(&eddr,"-")) die_nomem();
      if (!stralloc_0(&eddr)) die_nomem();
      case_lowerb(eddr.s,eddr.len);
      if (constmap(&mapbmf,eddr.s + at,eddr.len - at - 1)) return -4;
    }

/* '=' extended address for WELLKNOWN senders */

    else if (at && rlen >= addr.len - at - 1) {
      dlen = addr.len - at - 2;
      eddr.len = 0;
      if (!stralloc_copyb(&eddr,addr.s,addr.len - 1)) die_nomem();
      if (!stralloc_append(&eddr,"=")) die_nomem();
      if (!stralloc_0(&eddr)) die_nomem();
      case_lowerb(eddr.s,eddr.len);
      if (str_diffn(remotehost + rlen - dlen,eddr.s + at + 1,dlen)) 
        if (constmap(&mapbmf,eddr.s + at,eddr.len - at - 1)) return -3;
    }

/* '~' extended address for MISMATCHED Domains */

    if (case_diffs(remotehost,"unknown"))
      if (case_diffrs(remotehost,addr.s + at + 1)) {
        j = 0;
        do { 
          eddr.len = 0; 
          if (!stralloc_copys(&eddr,"~")) die_nomem();
          if (!stralloc_cats(&eddr,remotehost + j)) die_nomem();
          if (!stralloc_0(&eddr)) die_nomem();
          if (constmap(&mapbmf,eddr.s,eddr.len - 1)) return -2;
          j = byte_chr(remotehost + j,rlen - j,'.') + j + 1;
        }
        while (j > 0 && rlen - j > 0);
      }

/* Standard */

    if (constmap(&mapbmf,addr.s,addr.len - 1)) return -1;
    if (at && at < addr.len)
      if (constmap(&mapbmf,addr.s + at,addr.len - at - 1)) return -1;

/* Wildmating */

    i = k = 0;
    for (j = 0;j < bmf.len;++j)
      if (!bmf.s[j]) {
        subvalue = bmf.s[i] != '!';
        if (!subvalue) i++;
        if ((k != subvalue) && wildmat(addr.s,bmf.s + i)) k = subvalue;
        i = j + 1;
      }
    return k;
  }

  return 0;
}

int brtcheck()
{
  int i;
  int j;
  int k = 0;
  char subvalue;

  if (brtok) {
    if (constmap(&mapbrt,addr.s,addr.len - 1)) return -2;

    int at = byte_rchr(addr.s,addr.len,'@');
    if (at < addr.len)
      if (constmap(&mapbrt,addr.s + at,addr.len - at - 1)) return -1;

    i = 0;
    for (j = 0;j < brt.len;++j)
      if (!brt.s[j]) {
        subvalue = brt.s[i] != '!';
        if (!subvalue) i++;
        if ((k != subvalue) && wildmat(addr.s,brt.s + i)) k = subvalue;
        i = j + 1;
      }
    return k;
  }
  return 0;
}

int bhelocheck()
{
  int i;
  int j;
  int k = 0;
  char subvalue;
 
  if (badhelook && helohost.len) {
    eddr.len = 0;							/* helohost! */
    if (!stralloc_copyb(&eddr,helohost.s,helohost.len - 1)) die_nomem();
    if (!stralloc_append(&eddr,"!")) die_nomem();
    if (!stralloc_0(&eddr)) die_nomem();
    if (constmap(&mapbhlo,eddr.s,eddr.len - 1)) return -3;

    if (constmap(&mapbhlo,helohost.s,helohost.len - 1)) return -1;

    i = 0;
    for (j = 0;j < badhelo.len;++j)
      if (!badhelo.s[j]) {
        subvalue = badhelo.s[i] != '!';
        if (!subvalue) i++;
        if ((k != subvalue) && wildmat(helohost.s,badhelo.s + i)) k = subvalue;
        i = j + 1;
      }
    return k;
  }
  return 0;
}

int dnsq(arg,type) char *arg, *type;
{
  unsigned int random;
  int at;
  int i = 0;
  int len;

  len = str_len(arg);
  if (len < 1) return -2;

  sa.len = 0;
  if (arg[len-1] == ' ') len--;	/* trailing blank */
  if (len < 1) return -2;

  at = byte_rchr(arg,len,'@');
  if (at < len) {
    if (!stralloc_copyb(&sa,arg + at + 1,len - at - 1)) die_nomem();
  } else
    if (!stralloc_copyb(&sa,arg,len)) die_nomem();

  dns_init(0);
  random = now() + (getpid() << 16);
  switch(*type) {
    case 'A':  i = dns_ip(&ia,&sa); break;
    case 'M':  i = dns_mxip(&ia,&sa,random); break;
  }
  switch(i) {
    case DNS_HARD: return 1;
    case DNS_SOFT: out("451 DNS temporary failure (#4.3.0)\r\n"); return -1;
    case DNS_MEM:  die_nomem();
  }

  return 0;
}

int addrallowed(char *add)
{
  int r;
  r = rcpthosts(add,str_len(add));
  if (r == -1) die_control();
  return r;
}

int rcptallowed()
{
  int r;
  r = recipients(addr.s,str_len(addr.s));
#ifdef PAM111421
  if (r == 111) die_recipients();
#endif
  if (r == -3) die_recipients();
  if (r == -2) die_nomem();
  if (r == -1) die_control();
  return r;
}

int localaddr(char *mf)
{
  int at;
  int mflen;

  mflen = str_len(mf);
  if (mflen < 1 ) return 0;

  if (localmf == 3) {
    if (!case_diffs(remoteinfo,mf)) return 2;
    return -3;
  }
  else  if (localmf == 2) 
    return mfrules(fdmav,remoteip,remotehost,remoteinfo,mf);
  else {
    if (str_len(localmfcheck) > 1) {
      case_lowerb(localmfcheck,str_len(localmfcheck));
      at = byte_rchr(mf,mflen,'@');
      if (at < mflen)
        if (!str_diffn(localmfcheck,mf + at + 1,mflen - at - 1)) return 2;
    }
    if (addrallowed(mf)) return 3;
    return -2;
  }
}

int seenmail = 0;
int flagbarf; /* defined if seenmail */
int flagrcpt;
int flagdnsmf;
int flagsize;
int rcptcount = 0;

stralloc mailfrom = {0};
stralloc rcptto = {0};
stralloc user = {0};
stralloc fuser = {0};
stralloc mfparms = {0};

int mailfrom_size(arg) char *arg;
{
  long r;
  unsigned long sizebytes = 0;

  scan_ulong(arg,&r);
  sizebytes = r;
  if (databytes) if (sizebytes > databytes) return 1;
  return 0;
}

void mailfrom_auth(arg,len)
char *arg;
int len;
{
  if (!stralloc_copys(&fuser,"")) die_nomem();
  if (case_starts(arg,"<>")) { if (!stralloc_cats(&fuser,"unknown")) die_nomem(); }
  else
    while (len) {
      if (*arg == '+') {
        if (case_starts(arg,"+3D")) { arg = arg + 2; len = len - 2; if (!stralloc_cats(&fuser,"=")) die_nomem(); }
        if (case_starts(arg,"+2B")) { arg = arg + 2; len = len - 2; if (!stralloc_cats(&fuser,"+")) die_nomem(); }
      }
  else
    if (!stralloc_catb(&fuser,arg,1)) die_nomem();
    arg++; len--;
  }
  if (!stralloc_0(&fuser)) die_nomem();
  if (!remoteinfo) {
    remoteinfo = fuser.s;
    if (!env_unset("TCPREMOTEINFO")) die_read();
    if (!env_put2("TCPREMOTEINFO",remoteinfo)) die_nomem();
  }
}

void mailfrom_parms(arg) char *arg;
{
  int i;
  int len;

  len = str_len(arg);
  if (!stralloc_copys(&mfparms,"")) die_nomem;
  i = byte_chr(arg,len,'>');
  if (i > 4 && i < len) {
    while (len) {
      arg++; len--;
      if (*arg == ' ' || *arg == '\0' ) {
        if (case_starts(mfparms.s,"SIZE=")) if (mailfrom_size(mfparms.s + 5)) { flagsize = 1; return; }
        if (case_starts(mfparms.s,"AUTH=")) mailfrom_auth(mfparms.s + 5,mfparms.len - 5);
        if (!stralloc_copys(&mfparms,"")) die_nomem;
      }
      else
        if (!stralloc_catb(&mfparms,arg,1)) die_nomem;
    }
  }
}

/* this file is too long ----------------------------------------- SMTP DIALOG */

void smtp_helo(arg) char *arg;
{
  smtp_greet("250 "); out("\r\n");
  seenmail = 0; rcptcount = 0; seenhelo++; dohelo(arg); 
}
void smtp_ehlo(arg) char *arg;
{
  char size[FMT_ULONG];
  size[fmt_ulong(size,(unsigned long) databytes)] = 0;  
  smtp_greet("250-"); out("\r\n");
  out("250-PIPELINING\r\n250-8BITMIME\r\n");
  if (starttls && !seenttls) out("250-STARTTLS\r\n");
  if (smtpauth) {
    if (smtpauth == 1 || smtpauth == 11) out("250-AUTH LOGIN PLAIN\r\n");
    if (smtpauth == 2 || smtpauth == 12) out("250-AUTH CRAM-MD5\r\n");
    if (smtpauth == 3 || smtpauth == 13) out("250-AUTH LOGIN PLAIN CRAM-MD5\r\n");
  }
  out("250 SIZE "); out(size); out("\r\n");
  seenhelo++; seenmail = 0; rcptcount = 0; dohelo(arg); 
}
void smtp_rset()
{
  seenmail = 0; rcptcount = 0; seenauth = 0; seenttls = 0;
  mailfrom.len = 0; rcptto.len = 0; tlsinfo.len = 0; ssin.p = 0;
  out("250 flushed\r\n");
}
void smtp_starttls()
{
  if (!starttls)  { err_unimpl; return; }
  out("220 Ready to start TLS (#5.7.0)\r\n");
  flush();

  if (!starttls_init()) die_starttls();
  seenttls = 1;

  if (!starttls_info()) die_starttls();
  if (!modssl_info()) die_starttls();

/* reset SMTP state */

  seenhelo = 0; seenmail = 0; rcptcount = 0; seenauth = 0;
  helohost.len = 0; mailfrom.len = 0; rcptto.len = 0; ssin.p = 0;
}
void smtp_mail(arg) char *arg;
{
  if (smtpauth) 
    if (smtpauth > 10 && !seenauth) { err_submission(); return; }
  if (!addrparse(arg)) { err_syntax(); return; }
  flagsize = 0;
  rcptcount = 0;
  mailfrom_parms(arg);
  seenmail++;
  if (relayclient) { 
    if (localmf) flagmav = localaddr(addr.s);
    switch(flagmav) {
      case -9: die_nomem(); break;
      case  2: if (!stralloc_cats(&protocol,"M")) die_nomem(); break;
      default: break;
    }
  }
  if (!stralloc_copys(&rcptto,"")) die_nomem();
  if (!stralloc_copys(&mailfrom,addr.s)) die_nomem();
  if (!stralloc_0(&mailfrom)) die_nomem();

  if (!env_unset("MAILFROM")) die_read();
  if (!env_put2("MAILFROM",mailfrom.s)) die_nomem();

  flagbarf = bmfcheck(); 
  if (flagbarf != -111) 
    if (mfdnscheck) flagdnsmf = dnsq(mailfrom.s,"M");
  if (!stralloc_0(&protocol)) die_nomem(); 
  out("250 ok\r\n");
}
void smtp_rcpt(arg) char *arg; {
  if (!seenmail) { err_wantmail(); return; }
  if (!addrparse(arg)) { err_syntax(); return; }
  if (!str_len(addr.s)) { err_nullrcpt("Reject::RCPT::Empty",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); return; }
  rcptcount++;

/* this file is too long --------------------------------- Sesssion checks */

  if (starttls == 2 && !seenttls) {		/* STTARTTLS rejects */
    err_tlsreq("Reject::TLS::missing",protocol.s,remoteip,remotehost,mailfrom.s,addr.s);
    return;
  }

  if (smtpauth > 10 && !seenauth) {		 /* Auth rejects */
    err_authreq("Reject::AUTH::missing",protocol.s,remoteip,remotehost,mailfrom.s,addr.s);
    return; 
  }

/* this file is too long --------------------------------- Split Horizon envelope checks */

  if (!relayclient) {
    if (!seenhelo && helocheck) 		/* Helo rejects */
    if (str_len(helocheck) == 1) { 
      err_helo("Reject::SNDR::Bad_Helo",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"0"); 
      return;
    }
    if (flagbadhelo) { 
       switch(flagbadhelo) {
         case -2: badhelocond = "!"; break;
         case -1: badhelocond = "."; break;
         default: badhelocond = "*"; break;
       }
       err_helo("Reject::SNDR::Bad_Helo",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badhelocond);
       return;
    }
    if (flagdnshelo) { 
      err_helo("Reject::SNDR::DNS_Helo",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badhelocond); 
      return; 
    }
    if (flagdnsmf > 0) { 			/* Mail from rejects */
      err_mfdns("Reject::ORIG::DNS_MF",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
      return; 
    }
    if (!addrallowed(addr.s)) { 		/* Relaying rejects */
      err_nogateway("Reject::SNDR::Invalid_Relay",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); 
      return; 
    }

    if (tarpitcount && flagerrcpts >= tarpitcount) { 	/* Tarpitting et al. */
      if (tarpitdelay == 999) flagnotorious++;
      err_rcpts("Reject::RCPT::Toomany_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); 
      return; 
    }
    if (tarpitcount && rcptcount >= tarpitcount)
      if (tarpitdelay > 0 && tarpitdelay < 999) sleep(tarpitdelay); 

    flagrcpt = rcptallowed();			/* Rcpt to rejects */
    if (!flagrcpt) {
      err_recipient("Reject::RCPT::Failed_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); 
      flagerrcpts++;
      return; 
    } 
  }					 		

/* this file is too long --------------------------------- Local checks */

  else {
    if (flagmav < 0) { 
      err_mav("Reject::ORIG::Invalid_Mailfrom",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
      return;
    }
    --addr.len;
    if (!stralloc_cats(&addr,relayclient)) die_nomem();
    if (!stralloc_0(&addr)) die_nomem();
  }						

/* this file is too long --------------------------------- Common checks */

  if (flagbarf && flagbarf != -111) { 
    switch(flagbarf) {
      case -1: badmailcond = "@"; break;
      case -2: badmailcond = "~"; break;
      case -3: badmailcond = "="; break;
      case -4: badmailcond = "-"; break;
      case -5: badmailcond = "+"; break;
      default: badmailcond = "*"; break;
    }
    err_bmf("Reject::ORIG::Bad_Mailfrom",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badmailcond); 
    return; 
  }

  if (brtcheck()) {
    err_brt("Reject::RCPT::Bad_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
    return;
  }

  if (flagsize) { 
    err_size(); 
    smtp_logg("Reject::DATA::Invalid_Size",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
    return;
  }

  if (maxrcptcount && rcptcount > maxrcptcount) {
    err_rcpts("Reject::RCPT::Toomany_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); 
    return; 
  }

/* this file is too long --------------------------------- Checks done; mailfrom/recipient accepted */

  if (!stralloc_cats(&rcptto,"T")) die_nomem();
  if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
  if (!stralloc_0(&rcptto)) die_nomem();

  if (!stralloc_cats(&mailto,addr.s)) die_nomem();
  if (!stralloc_cats(&mailto," ")) die_nomem();
  if (!stralloc_copys(&deliverto,mailto.s)) die_nomem();
  if (!stralloc_0(&deliverto)) die_nomem();

  if (!env_unset("RCPTTO")) die_read();
  if (!env_put2("RCPTTO",deliverto.s)) die_nomem();

  out("250 ok\r\n");

/* this file is too long --------------------------------- Additional logging */

  if (flagmav > 0) 
    smtp_logg("Accept::ORIG::Local_Sender",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
  else if (relayclient) 
    smtp_logg("Accept::SNDR::Relay_Client",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
  else
    switch(flagrcpt) {
      case 1:  smtp_logg("Accept::RCPT::Recipients_Cdb",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); break;
      case 2:  smtp_logg("Accept::RCPT::Recipients_Pam",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); break; 
      case 3:  smtp_logg("Accept::RCPT::Recipients_Wild",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); break;
      default: smtp_logg("Accept::RCPT::Rcpthosts_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); break;
    }
}

struct qmail qqt;
unsigned long bytestooverflow = 0;

stralloc line = {0};
stralloc base64types = {0};
stralloc badmimetype = {0};
stralloc badloadertype = {0};

unsigned int nolines = 0;
unsigned int flagb64 = 0;       /* lineno with BASE64MESSAGE */
unsigned int flagbase = 0;      /* lineno with actual base64 content */
unsigned int flagblank = 0;

void put(ch)
char *ch;
{
  uint32 dlen;
  int i;

  if (flagmimetype > 0 || flagloadertype > 0 ) {
    if (line.len < 1025)
      if (!stralloc_catb(&line,ch,1)) die_nomem();      /* Reassamble chars to line; prepend with 'L' */

    if (*ch == '\n') {
      nolines++;
      if (line.len == 2) { flagblank = nolines; flagbase = 0; }

      if (*(line.s+1) == 'C' || *(line.s+1) == 'c')
        if (case_startb(line.s+1,line.len-2,BASE64MESSAGE)) flagb64 = nolines;
      if (flagb64 && nolines == flagblank+1 && line.len > MIMETYPE_LEN+2) flagbase = nolines;
      if (*(line.s+1) == '-')  { flagb64 = 0; flagbase = 0; }

      if (flagmimetype > 0 && flagbase == nolines) {                             /* badmimetype */
        if (!stralloc_catb(&base64types,line.s+1,MIMETYPE_LEN)) die_nomem();
        if (!stralloc_0(&base64types)) die_nomem();

        if (flagmimetype > 1) {
          if (cdb_seek(fdbmt,line.s+1,MIMETYPE_LEN,&dlen)) {
            if (!stralloc_copyb(&badmimetype,line.s+1,MIMETYPE_LEN)) die_nomem();
            if (!stralloc_0(&badmimetype)) die_nomem();
            if (!stralloc_cats(&rcptto,"M")) die_nomem();
            if (!stralloc_0(&rcptto)) die_nomem(); 
            qmail_fail(&qqt);
            flagmimetype = -1;
          }
        }
      }

      if (flagbase && line.len > LOADER_LEN + 2) {
        if (flagloadertype == 1 || flagmimetype == 1 || flagmimetype == 3) {
          for ( i = 0; i < line.len - LOADER_LEN; ++i ) {
            if (flagloadertype == 1 && *(line.s+i) == *badloaderinit) {          /* badloadertype */
              if (cdb_seek(fdblt,line.s+i,LOADER_LEN,&dlen)) {
                if (!stralloc_copyb(&badloadertype,line.s+i,LOADER_LEN)) die_nomem();
                if (!stralloc_0(&badloadertype)) die_nomem();
                if (!stralloc_cats(&rcptto,"L")) die_nomem();
                if (!stralloc_0(&rcptto)) die_nomem(); 
                qmail_fail(&qqt);
                flagloadertype = -1;
              }
            }
            if (flagmimetype == 1 || flagmimetype == 3) {
              if (*(line.s+i) == ' ' || *(line.s+i) == '\t') {                   /* white spaces */
                if (!stralloc_copyb(&badmimetype,line.s+i-2,MIMETYPE_LEN)) die_nomem();
                if (!stralloc_0(&badmimetype)) die_nomem();
                if (!stralloc_cats(&rcptto,"M")) die_nomem();
                if (!stralloc_0(&rcptto)) die_nomem(); 
                qmail_fail(&qqt);
                flagmimetype = -2;
              }
            }
          }
        }
      }
      line.len = 0;
      if (!stralloc_copys(&line,"L")) die_nomem();
    }
  }

  if (bytestooverflow)
    if (!--bytestooverflow)
      qmail_fail(&qqt);
  qmail_put(&qqt,ch,1);
}

void blast(hops)
int *hops;
{
  char ch;
  int state;
  int seencr;
  int flaginheader;
  int pos; /* number of bytes since most recent \n, if fih */
  int flagmaybex; /* 1 if this line might match RECEIVED, if fih */
  int flagmaybey; /* 1 if this line might match \r\n, if fih */
  int flagmaybez; /* 1 if this line might match DELIVERED, if fih */

  state = 1;
  *hops = 0;
  flaginheader = 1;
  pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; seencr = 0;
  for (;;) {
    substdio_get(&ssin,&ch,1);
    if (ch == '\n')
      {
       if (seencr == 0)
         { substdio_seek(&ssin,-1); ch = '\r'; }
      }
    if (ch == '\r') seencr = 1; else seencr = 0;
    if (flaginheader) {
      if (pos < 9) {
        if (ch != "delivered"[pos]) if (ch != "DELIVERED"[pos]) flagmaybez = 0;
        if (flagmaybez) if (pos == 8) ++*hops;
        if (pos < 8)
          if (ch != "received"[pos]) if (ch != "RECEIVED"[pos]) flagmaybex = 0;
        if (flagmaybex) if (pos == 7) ++*hops;
        if (pos < 2) if (ch != "\r\n"[pos]) flagmaybey = 0;
        if (flagmaybey) if (pos == 1) flaginheader = 0;
        ++pos;
      }
      if (ch == '\n') { pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; }
    }
    switch(state) {
      case 0:
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 4; continue; }
        break;
      case 1: /* \r\n */
        if (ch == '\n') straynewline();
        if (ch == '.') { state = 2; continue; }
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 2: /* \r\n + . */
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 3; continue; }
        state = 0;
        break;
      case 3: /* \r\n + .\r */
        if (ch == '\n') return;
        put(".");
        put("\r");
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 4: /* + \r */
        if (ch == '\n') { state = 1; break; }
        if (ch != '\r') { put("\r"); state = 0; }
    }
    put(&ch);
  }
}

char accept_buf[FMT_ULONG];
void acceptmessage(qp) unsigned long qp;
{
  datetime_sec when;
  when = now();
  out("250 ok ");
  accept_buf[fmt_ulong(accept_buf,(unsigned long) when)] = 0;
  out(accept_buf);
  out(" qp ");
  accept_buf[fmt_ulong(accept_buf,qp)] = 0;
  out(accept_buf);
  out("\r\n");
}

void smtp_data() {
  int hops;
  unsigned long qp;
  char *qqx;
 
  if (!seenmail) { err_wantmail(); return; }
  if (!rcptto.len) { err_wantrcpt(); return; }
  if (flagnotorious) { err_notorious(); return; }
  seenmail = 0;
  if (databytes) bytestooverflow = databytes + 1;

  if (!stralloc_copys(&addr,"")) die_nomem();
  if (!stralloc_cats(&addr,rcptto.s+1)) die_nomem();
  if (!stralloc_0(&addr)) die_nomem();

  if (qmail_open(&qqt) == -1) { err_qqt(); return; }
  qp = qmail_qp(&qqt);
  out("354 go ahead\r\n");
 
  received(&qqt,protocol.s,local,remoteip,remotehost,remoteinfo,fakehelo,tlsinfo.s,rblinfo.s); 
  if (spf) spfheader(&qqt,spfinfo.s,spfinfo.len,remoteip,fakehelo,mailfrom.s,addr.s);
  blast(&hops);
  hops = (hops >= MAXHOPS);
  if (hops) qmail_fail(&qqt);
  if (base64 && base64types.len == 0) {
    if (!stralloc_cats(&rcptto,"Q")) die_nomem();
    if (!stralloc_0(&rcptto)) die_nomem(); 
  } 
  qmail_from(&qqt,mailfrom.s);
  qmail_put(&qqt,rcptto.s,rcptto.len);

  qqx = qmail_close(&qqt);
  if (!*qqx) { acceptmessage(qp); return; }
  if (hops) { out("554 too many hops, this message is looping (#5.4.6)\r\n"); return; }
  if (databytes) 
    if (!bytestooverflow) {
       err_size();
       smtp_logg("Reject::DATA::Invalid_Size",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
       return;
    }
  if (flagmimetype < 0) { 
    err_data("Reject::DATA::Bad_MIME",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badmimetype.s);
    return; 
  }
  if (flagloadertype < 0) { 
    err_data("Reject::DATA::Bad_Loader",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badloadertype.s);
    return;
  }
  if (*qqx == 'S') { 
    err_data("Reject::DATA::Spam_Message",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"spam");
    return;
  }
  if (*qqx == 'A') { 
    err_data("Reject::DATA::MIME_Attach",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"MIME");
    return;
  }
  if (*qqx == 'V') { 
    if (qhpsi)
      err_data("Reject::DATA::Virus_Infected",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,qhpsi);
    else
      err_data("Reject::DATA::Virus_Infected",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"AV scanner");
    return;
  }
  if (*qqx == 'D') out("554 "); else out("451 "); 
  out(qqx + 1);
  out("\r\n");
}

/* this file is too long ----------------------------------------- SMTP AUTH */

char unique[FMT_ULONG + FMT_ULONG + 3];
static stralloc authin = {0};   /* input from SMTP client */
static stralloc pass = {0};     /* plain passwd or digest */
static stralloc resp = {0};     /* b64 response */
static stralloc chal = {0};     /* CRAM-MD5 plain challenge */
static stralloc slop = {0};     /* CRAM-MD5 b64 challenge */

char **childargs;
char ssauthbuf[512];
substdio ssauth = SUBSTDIO_FDBUF(safewrite,3,ssauthbuf,sizeof(ssauthbuf));

int authgetl(void) {
  int i;

  if (!stralloc_copys(&authin,"")) die_nomem();
  for (;;) {
    if (!stralloc_readyplus(&authin,1)) die_nomem(); /* XXX */
    i = substdio_get(&ssin,authin.s + authin.len,1);
    if (i != 1) die_read();
    if (authin.s[authin.len] == '\n') break;
    ++authin.len;
  }

  if (authin.len > 0) if (authin.s[authin.len - 1] == '\r') --authin.len;
  authin.s[authin.len] = 0;
  if (*authin.s == '*' && *(authin.s + 1) == 0) { return err_authabrt(); }
  if (authin.len == 0) { return err_input(); }
  return authin.len;
}

int authenticate(void)
{
  int child;
  int wstat;
  int pi[2];

  if (!stralloc_0(&user)) die_nomem();
  if (!stralloc_0(&pass)) die_nomem();
  if (!stralloc_0(&chal)) die_nomem();

  if (pipe(pi) == -1) return err_pipe();
  switch(child = fork()) {
    case -1:
      return err_fork();
    case 0:
      close(pi[1]);
      if (fd_copy(3,pi[0]) == -1) return err_pipe();
      sig_pipedefault();
      execvp(*childargs, childargs);
      _exit(1);
  }
  close(pi[0]);

  substdio_fdbuf(&ssauth,write,pi[1],ssauthbuf,sizeof ssauthbuf);
  if (substdio_put(&ssauth,user.s,user.len) == -1) return err_write();
  if (substdio_put(&ssauth,pass.s,pass.len) == -1) return err_write();
  if (smtpauth == 2 || smtpauth == 3 || smtpauth == 12) 
    if (substdio_put(&ssauth,chal.s,chal.len) == -1) return err_write();
  if (substdio_flush(&ssauth) == -1) return err_write();

  close(pi[1]);
  if (!stralloc_copys(&chal,"")) die_nomem(); 
  if (!stralloc_copys(&slop,"")) die_nomem(); 
  byte_zero(ssauthbuf,sizeof ssauthbuf);
  if (wait_pid(&wstat,child) == -1) return err_child();
  if (wait_crashed(wstat)) return err_child();
  if (wait_exitcode(wstat)) { sleep(AUTHSLEEP); return 1; } /* no */
  return 0; /* yes */
}

int auth_login(arg) char *arg;
{
  int r;

  if (*arg) {
    if (r = b64decode(arg,str_len(arg),&user) == 1) return err_input();
  }
  else {
    out("334 VXNlcm5hbWU6\r\n"); flush();       /* Username: */
    if (authgetl() < 0) return -1;
    if (r = b64decode(authin.s,authin.len,&user) == 1) return err_input();
  }
  if (r == -1) die_nomem();

  out("334 UGFzc3dvcmQ6\r\n"); flush();         /* Password: */

  if (authgetl() < 0) return -1;
  if (r = b64decode(authin.s,authin.len,&pass) == 1) return err_input();
  if (r == -1) die_nomem();

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

int auth_plain(arg) char *arg;
{
  int r, id = 0;

  if (*arg) {
    if (r = b64decode(arg,str_len(arg),&resp) == 1) return err_input();
  }
  else {
    out("334 \r\n"); flush();
    if (authgetl() < 0) return -1;
    if (r = b64decode(authin.s,authin.len,&resp) == 1) return err_input();
  }
  if (r == -1 || !stralloc_0(&resp)) die_nomem();
  while (resp.s[id]) id++;                       /* "authorize-id\0userid\0passwd\0" */

  if (resp.len > id + 1)
    if (!stralloc_copys(&user,resp.s + id + 1)) die_nomem();
  if (resp.len > id + user.len + 2)
    if (!stralloc_copys(&pass,resp.s + id + user.len + 2)) die_nomem();

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

int auth_cram()
{
  int i, r;
  char *s;

  s = unique;						/* generate challenge */
  s += fmt_uint(s,getpid());
  *s++ = '.';
  s += fmt_ulong(s,(unsigned long) now());
  *s++ = '@';
  *s++ = 0;
  if (!stralloc_copys(&chal,"<")) die_nomem(); 
  if (!stralloc_cats(&chal,unique)) die_nomem();
  if (!stralloc_cats(&chal,local)) die_nomem();
  if (!stralloc_cats(&chal,">")) die_nomem();
  if (b64encode(&chal,&slop) < 0) die_nomem();
  if (!stralloc_0(&slop)) die_nomem();

  out("334 ");                                          /* "334 base64_challenge \r\n" */
  out(slop.s);
  out("\r\n");
  flush();

  if (authgetl() < 0) return -1;                        /* got response */
  if (r = b64decode(authin.s,authin.len,&resp) == 1) return err_input();
  if (r == -1 || !stralloc_0(&resp)) die_nomem();

  i = str_rchr(resp.s,' ');
  s = resp.s + i;
  while (*s == ' ') ++s;
  resp.s[i] = 0;
  if (!stralloc_copys(&user,resp.s)) die_nomem();       /* userid */
  if (!stralloc_copys(&pass,s)) die_nomem();    	/* digest */

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

struct authcmd {
  char *text;
  int (*fun)();
} authcmds[] = { 
  { "login",auth_login } 
, { "plain",auth_plain } 
, { "cram-md5",auth_cram } 
, { 0,err_noauth } 
};

void smtp_auth(arg)
char *arg;
{
  int i;
  char *cmd = arg;

  if (!*childargs) { out("503 auth not available (#5.3.3)\r\n"); return; }
  if (seenauth) { err_authd(); return; }
  if (seenmail) { err_authmail(); return; }

  if (!stralloc_copys(&user,"")) die_nomem();
  if (!stralloc_copys(&pass,"")) die_nomem();
  if (!stralloc_copys(&resp,"")) die_nomem();
  if (!stralloc_copys(&chal,"")) die_nomem();		/* only needed for CRAM-MD5 */

  i = str_chr(cmd,' ');					/* get AUTH type */
  arg = cmd + i;
  while (*arg == ' ') ++arg;
  cmd[i] = 0;

  for (i = 0;authcmds[i].text;++i)
    if (case_equals(authcmds[i].text,cmd)) break;

  if (!env_unset("AUTHPROTOCOL")) die_read();
  if (!env_put2("AUTHPROTOCOL",authcmds[i].text)) die_nomem();
  if (!env_unset("AUTHUSER")) die_read();
  if (!env_put2("AUTHUSER",user.s)) die_nomem();

  switch (authcmds[i].fun(arg)) {
    case 0:
      seenauth = 1;
      if (!stralloc_cats(&protocol,"A")) die_nomem();
      relayclient = "";
      remoteinfo = user.s;
      if (!env_unset("TCPREMOTEINFO")) die_read();
      if (!env_put2("TCPREMOTEINFO",remoteinfo)) die_nomem();
      if (!env_put2("RELAYCLIENT",relayclient)) die_nomem();
      out("235 ok, go ahead (#2.0.0)\r\n");
      smtp_loga("Accept::AUTH::","ESMTPA",remoteip,remotehost,user.s,authcmds[i].text);
      break;
    case 1:
      if (!stralloc_cats(&protocol,"A")) die_nomem();
      if (!stralloc_0(&protocol)) die_nomem();
      err_authfail("Reject::AUTH::",protocol.s,remoteip,remotehost,user.s,authcmds[i].text);
  }

}

/* this file is too long --------------------------------------------- GO ON */

struct commands smtpcommands[] = {
  { "rcpt", smtp_rcpt, 0 }
, { "mail", smtp_mail, 0 }
, { "data", smtp_data, flush }
, { "auth", smtp_auth, flush }
, { "quit", smtp_quit, flush }
, { "helo", smtp_helo, flush }
, { "ehlo", smtp_ehlo, flush }
, { "rset", smtp_rset, 0 }
, { "help", smtp_help, flush }
, { "noop", err_noop, flush }
, { "vrfy", err_vrfy, flush }
, { "starttls", smtp_starttls, flush }
, { 0, err_unimpl, flush }
} ;

int main(argc,argv)
int argc;
char **argv;
{
  childargs = argv + 1;
  sig_pipeignore();
  if (chdir(auto_qmail) == -1) die_control();
  setup();
  smtpdlog_init();
  if (ipme_init() != 1) die_ipme();
  smtp_greet("220 ");
  out(" ESMTP\r\n");
  if (commands(&ssin,&smtpcommands) == 0) die_read();
  die_nomem();

  return 0;
}
