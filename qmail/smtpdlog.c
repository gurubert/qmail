#include "readwrite.h"
#include "substdio.h"
#include "env.h"
#include "fmt.h"
#include "exit.h"
#include "smtpdlog.h"
#define FDLOG 2

char *reply550hlo;
char *reply550mbx;
char *reply552siz;
char *reply553bmf;
char *reply553brt;
char *reply553ngw;
char *reply553env;
char *reply553inv;
char *reply554cnt;

char strnum[FMT_ULONG];
char sslogbuf[512];
substdio sslog = SUBSTDIO_FDBUF(write,FDLOG,sslogbuf,sizeof(sslogbuf));

smtpdlog_init()
{
  reply550hlo = env_get("REPLY_HELO");
  reply550mbx = env_get("REPLY_MAILBOX");
  reply552siz = env_get("REPLY_MAXSIZE");
  reply553bmf = env_get("REPLY_BADMAILFROM");
  reply553brt = env_get("REPLY_BADRCPTTO");
  reply553env = env_get("REPLY_SENDEREXIST");
  reply553ngw = env_get("REPLY_NOGATEWAY");
  reply553inv = env_get("REPLY_SENDERINVALID");
  reply554cnt = env_get("REPLY_CONTENT");
}

static void logs(s) char *s; { if (substdio_puts(&sslog,s) == -1) _exit(1); }  /* single string */
static void logp(s) char *s; { logs(" P:"); logs(s); }				/* protocol */
static void logc(s1,s2) char *s1, *s2; { logs(" S:"); logs(s1); logs(":"); logs(s2); }                                 /* client */
static void logh(s1,s2,s3) char *s1, *s2, *s3; { logs(" S:"); logs(s1); logs(":"); logs(s2); logs(" H:"); logs(s3); }  /* host */
static void logf(s) char *s; { logs(" F:"); logs(s); }                         /* mailfrom */
static void logt(s) char *s; { logs(" T:"); logs(s); }                         /* rcptto */
static void logi(s) char *s; { logs(" '"); logs(s); logs("'"); }               /* information */
static void logn(s) char *s; { if (substdio_puts(&sslog,s) == -1) _exit(1); if (substdio_flush(&sslog) == -1) _exit(1); } /* end */
static void logpid() { strnum[fmt_ulong(strnum,getpid())] = 0; logs("qmail-smtpd: pid "); logs(strnum); logs(" "); }

void smtp_loga(s1,s2,s3,s4,s5,s6) char *s1, *s2, *s3, *s4, *s5, *s6;
  { logpid(); logs(s1); logs(s6); logp(s2); logc(s3,s4); logs(" ?="); logi(s5); logn("\n"); }		/* Auth info */
void smtp_logt(s1,s2,s3,s4,s5,s6) char *s1, *s2, *s3, *s4, *s5, *s6;
  { logpid(); logs(s1); logs(s6); logp(s2); logc(s3,s4); logs(" !="); logi(s5); logn("\n"); }	        /* TLS info */
void smtp_logg(s1,s2,s3,s4,s5,s6,s7) char *s1, *s2, *s3, *s4, *s5, *s6, *s7;
  { logpid(); logs(s1); logp(s2); logh(s3,s4,s5); logf(s6); logt(s7); logn("\n"); }			/* Generic */
void smtp_logi(s1,s2,s3,s4,s5,s6,s7,s8) char *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8;
  { logpid(); logs(s1); logp(s2); logh(s3,s4,s5); logf(s6); logt(s7); logi(s8); logn("\n"); }		/* Generic + Info */

void die_read() { _exit(1); }
void die_alarm() { out("451 timeout (#4.4.2)\r\n"); flush(); _exit(1); }
void die_nomem() { out("421 out of memory (#4.3.0)\r\n"); flush(); _exit(1); }
void die_control() { out("421 unable to read controls (#4.3.0)\r\n"); flush(); _exit(1); }
void die_ipme() { out("421 unable to figure out my IP addresses (#4.3.0)\r\n"); flush(); _exit(1); }
void die_starttls() { out("454 TLS not available due to temporary reason (#5.7.3)\r\n"); flush(); _exit(1); }
void die_recipients() { out("421 unable to check recipients (#4.3.0)\r\n"); flush(); _exit(1); }

void err_unimpl() { out("500 unimplemented (#5.5.1)\r\n"); }
void err_syntax() { out("555 syntax error (#5.5.4)\r\n"); }
void err_noop() { out("250 ok\r\n"); }
void err_vrfy() { out("252 send some mail, i'll try my best\r\n"); }
void err_qqt() { out("451 qqt failure (#4.3.0)\r\n"); }

int err_child() { out("454 problem with child and I can't auth (#4.3.0)\r\n"); return -1; }
int err_fork() { out("454 child won't start and I can't auth (#4.3.0)\r\n"); return -1; }
int err_pipe() { out("454 unable to open pipe and I can't auth (#4.3.0)\r\n"); return -1; }
int err_write() { out("454 unable to write pipe and I can't auth (#4.3.0)\r\n"); return -1; }

/* TLS */

int err_starttls() 
{ 
  out("454 TLS not available due to temporary reason (#5.7.3)\r\n");
  return -1; 
}
void err_tlsreq(s1,s2,s3,s4,s5,s6,s7)
{
  out("535 STARTTLS required (#5.7.1)\r\n"); 
  smtp_logg(s1,s2,s3,s4,s5,s6,s7); 
}

/* Helo */

void err_helo(s1,s2,s3,s4,s5,s6,s7,s8) char *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8;
{
  out("550 sorry, invalid HELO/EHLO greeting ");
  if (reply550hlo) out(reply550hlo);
  out(" (#5.7.1)\r\n");
  smtp_logi(s1,s2,s3,s4,s5,s6,s7,s8);
  return;
 }

/* Auth */

void err_authd() 
{ 
  out("503 you're already authenticated (#5.5.0)\r\n"); 
}
void err_authmail() 
{ 
  out("503 no auth during mail transaction (#5.5.0)\r\n");
}
int err_noauth() 
{ 
  out("504 auth type unimplemented (#5.5.1)\r\n"); 
  return -1; 
}
int err_authabrt() 
{ 
  out("501 auth exchange canceled (#5.0.0)\r\n"); 
  return -1; 
}
int err_input() 
{ 
  out("501 malformed auth input (#5.5.4)\r\n"); 
  return -1; 
}
void err_authfail(s1,s2,s3,s4,s5,s6)
{
  out("535 authentication failed (#5.7.1)\r\n"); smtp_loga(s1,s2,s3,s4,s5,s6); 
}
void err_authreq(s1,s2,s3,s4,s5,s6,s7)
{
  out("535 authentication required (#5.7.1)\r\n"); smtp_logg(s1,s2,s3,s4,s5,s6,s7); 
}
void err_submission() 
{ 
  out("530 Authorization required (#5.7.1) \r\n"); 
}

/* Mail From: */

void err_wantmail() { out("503 MAIL first (#5.5.1)\r\n"); }
void err_mav(s1,s2,s3,s4,s5,s6,s7)
{
  out("553 sorry, invalid sender address specified ");
  if (reply553inv) out(reply553inv);
  out(" (#5.7.1)\r\n");
  smtp_logg(s1,s2,s3,s4,s5,s6,s7);
  return;
}
void err_bmf(s1,s2,s3,s4,s5,s6,s7,s8) char *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8; 
{
  out("553 sorry, your envelope sender is in my badmailfrom list ");
  if (reply553bmf) out(reply553bmf);
  out(" (#5.7.1)\r\n");
  smtp_logi(s1,s2,s3,s4,s5,s6,s7,s8);
  return;
}
void err_mfdns(s1,s2,s3,s4,s5,s6,s7) char *s1, *s2, *s3, *s4, *s5, *s6, *s7; 
{
  out("553 sorry, your envelope sender must exist ");
  if (reply553env) out(reply553env);
  out(" (#5.7.1)\r\n");
  smtp_logg(s1,s2,s3,s4,s5,s6,s7);
  return;
}

/* Rcpt To: */

void err_wantrcpt() { out("503 RCPT first (#5.5.1)\r\n"); }
void err_nogateway(s1,s2,s3,s4,s5,s6,s7) char *s1, *s2, *s3, *s4, *s5, *s6, *s7; 
{
  out("553 sorry, that domain isn't in my list of allowed rcpthosts ");
  if (reply553ngw) out(reply553ngw);
  out(" (#5.7.1)\r\n");
  smtp_logg(s1,s2,s3,s4,s5,s6,s7);
  return;
}
void err_brt(s1,s2,s3,s4,s5,s6,s7,s8) char *s1, *s2, *s3, *s4, *s5, *s6, *s7;
{
  out("553 sorry, your envelope recipient is in my badrcptto list ");
  if (reply553brt) out(reply553brt);
  out(" (#5.7.1)\r\n");
  smtp_logg(s1,s2,s3,s4,s5,s6,s7);
  return;
}
void err_rcpts(s1,s2,s3,s4,s5,s6,s7) char *s1, *s2, *s3, *s4, *s5, *s6, *s7;
{
  out("452 sorry, too many recipients (#4.5.3)\r\n");   /* RFC 5321 */
  smtp_logg(s1,s2,s3,s4,s5,s6,s7);
  return;
}
void err_recipient(s1,s2,s3,s4,s5,s6,s7) char *s1, *s2, *s3, *s4, *s5, *s6, *s7;
{
  if (env_get("RECIPIENTS450"))
    out("450 sorry, mailbox currently unavailable (#4.2.1)\r\n");
  else {
    out("550 sorry, no mailbox by that name ");
    if (reply550mbx) out(reply550mbx); out(" (#5.7.1)\r\n");
  }
  smtp_logg(s1,s2,s3,s4,s5,s6,s7);
  return;
}

/* Data */

void straynewline() 
{ 
  out("451 See http://pobox.com/~djb/docs/smtplf.html.\r\n"); 
  flush(); 
  _exit(1); 
}
void err_notorious() 
{ 
  out("503 DATA command not accepted at this time (#5.5.1)\r\n");
  flush();
  _exit(1);
}
void err_size() { out("552 sorry, that message size exceeds my databytes limit "); }
void err_data(s1,s2,s3,s4,s5,s6,s7,s8) char *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8;
{
  out("554 sorry, invalid message content ");
  if (reply554cnt) out(reply554cnt);
  out(" (#5.3.2)\r\n");
  smtp_logi(s1,s2,s3,s4,s5,s6,s7,s8);
  return;
}
