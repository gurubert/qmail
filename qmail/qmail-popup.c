#include "commands.h"
#include "fd.h"
#include "sig.h"
#include "stralloc.h"
#include "substdio.h"
#include "alloc.h"
#include "wait.h"
#include "str.h"
#include "byte.h"
#include "now.h"
#include "fmt.h"
#include "exit.h"
#include "readwrite.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "env.h"
#include "starttls.h"

#define POP3SPORT "995"

void die() { _exit(1); }

int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutread(1200,fd,buf,len);
  if (r <= 0) die();
  return r;
}

int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutwrite(1200,fd,buf,len);
  if (r <= 0) die();
  return r;
}

char ssoutbuf[128];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

char ssinbuf[128];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

void puts(s) char *s;
{
  substdio_puts(&ssout,s);
}
void flush()
{
  substdio_flush(&ssout);
}
void err(s) char *s;
{
  puts("-ERR ");
  puts(s);
  puts("\r\n");
  flush();
}

/* Logging */

#define FDLOG 5
stralloc protocol = {0};  
stralloc auth = {0};
char *localport;
char *remoteip;
char *remotehost;

char strnum[FMT_ULONG];
char sslogbuf[512];
substdio sslog = SUBSTDIO_FDBUF(safewrite,FDLOG,sslogbuf,sizeof(sslogbuf));

void logs(s) char *s; { if(substdio_puts(&sslog,s) == -1) _exit(1); }
void logp(s) char *s; { logs(" P:"); logs(s); }
void logh(s1,s2) char *s1, *s2; { logs(" S:"); logs(s1); logs(":"); logs(s2); }  
void logu(s) char *s; { logs(" ?= '"); logs(s); logs("'"); }  
void logn(s) char *s; { if(substdio_puts(&sslog,s) == -1) _exit(1); if(substdio_flush(&sslog) == -1) _exit(1); }
void logpid() { strnum[fmt_ulong(strnum,getpid())] = 0; logs("qmail-popup: pid "); logs(strnum); logs(" "); }
void log_pop(s1,s2,s3,s4,s5,s6) char *s1, *s2, *s3, *s4, *s5, *s6;  
  { logpid(); logs(s1); logs(s2); logp(s3); logh(s4,s5), logu(s6), logn("\n"); }

void die_usage() { err("usage: popup hostname subprogram"); die(); }
void die_nomem() { err("out of memory"); die(); }
void die_pipe() { err("unable to open pipe"); die(); }
void die_write() { err("unable to write pipe"); die(); }
void die_fork() { err("unable to fork"); die(); }
void die_childcrashed() { err("aack, child crashed"); }
void die_badauth() { err("authorization failed"); }
void die_tls() { err("TLS startup failed"); die(); }

void err_syntax() { err("syntax error"); }
void err_wantuser() { err("USER first"); }
void err_authoriz() { err("authorization first"); }

void okay() { puts("+OK \r\n"); flush(); }
void pop3_quit() { okay(); die(); }

void poplog_init()
{
  if (!stralloc_copys(&protocol,"POP3")) die_nomem();
  localport = env_get("TCPLOCALPORT");
  if (!localport) localport = "unknown";
  if (!case_diffs(localport,POP3SPORT))
    if (!stralloc_cats(&protocol,"S")) die_nomem();
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
}

char unique[FMT_ULONG + FMT_ULONG + 3];
char *hostname;
stralloc username = {0};
int seenuser = 0;
char **childargs;
substdio ssup;
char upbuf[128];
int stls = 0;

void doanddie(user,userlen,pass)
char *user;
unsigned int userlen; /* including 0 byte */
char *pass;
{
  int child;
  int wstat;
  int pi[2];
 
  if (fd_copy(2,1) == -1) die_pipe(); 
  close(3);
  if (pipe(pi) == -1) die_pipe();
  if (pi[0] != 3) die_pipe();
  switch(child = fork()) {
    case -1:
      die_fork();
    case 0:
      close(pi[1]);
      sig_pipedefault();
      execvp(*childargs,childargs);
      _exit(1);
  }
  close(pi[0]);
  substdio_fdbuf(&ssup,write,pi[1],upbuf,sizeof upbuf);
  if (substdio_put(&ssup,user,userlen) == -1) die_write();
  if (substdio_put(&ssup,pass,str_len(pass) + 1) == -1) die_write();
  if (substdio_puts(&ssup,"<") == -1) die_write();
  if (substdio_puts(&ssup,unique) == -1) die_write();
  if (substdio_puts(&ssup,hostname) == -1) die_write();
  if (substdio_put(&ssup,">",2) == -1) die_write();
  if (substdio_flush(&ssup) == -1) die_write();
  close(pi[1]);
  byte_zero(pass,str_len(pass));
  byte_zero(upbuf,sizeof upbuf);
  if (wait_pid(&wstat,child) == -1) die();
  if (wait_crashed(wstat)) die_childcrashed();
  if (!stralloc_0(&auth)) die_nomem();
  if (!stralloc_0(&protocol)) die_nomem();
  if (wait_exitcode(wstat)) { 
    die_badauth(); 
    log_pop("Reject::AUTH::",auth.s,protocol.s,remoteip,remotehost,user); 
  }
  else
    log_pop("Accept::AUTH::",auth.s,protocol.s,remoteip,remotehost,user); 
  die();
}
void pop3_greet()
{
  char *s;
  s = unique;
  s += fmt_uint(s,getpid());
  *s++ = '.';
  s += fmt_ulong(s,(unsigned long) now());
  *s++ = '@';
  *s++ = 0;
  puts("+OK <");
  puts(unique);
  puts(hostname);
  puts(">\r\n");
  flush();
}
void pop3_user(arg) char *arg;
{
  if (!*arg) { err_syntax(); return; }
  okay();
  seenuser = 1;
  if (!stralloc_copys(&username,arg)) die_nomem(); 
  if (!stralloc_0(&username)) die_nomem(); 
}
void pop3_pass(arg) char *arg;
{
  if (!seenuser) { err_wantuser(); return; }
  if (!*arg) { err_syntax(); return; }
  if (!stralloc_copys(&auth,"User")) die_nomem();
  doanddie(username.s,username.len,arg);
}
void pop3_apop(arg) char *arg;
{
  char *space;
  space = arg + str_chr(arg,' ');
  if (!*space) { err_syntax(); return; }
  *space++ = 0;
  if (!stralloc_copys(&auth,"Apop")) die_nomem();
  doanddie(arg,space - arg,space);
}
void pop3_capa(arg) char *arg;
{
  puts("+OK capability list follows\r\n");
  puts("TOP\r\n");
  puts("UIDL\r\n");
  if (stls == 1)
    puts("STLS\r\n");
  puts(".\r\n");
  flush();
}
void pop3_stls(arg) char *arg;
{
  if (stls != 1)
    return err("STLS not available");
  puts("+OK starting TLS negotiation\r\n");
  flush();

  if (!starttls_init())
    die_tls();

  stls = 2;
  /* reset state */
  seenuser = 0;
  if (!stralloc_cats(&protocol,"S")) die_nomem();
}

struct commands pop3commands[] = {
  { "user", pop3_user, 0 }
, { "pass", pop3_pass, 0 }
, { "apop", pop3_apop, 0 }
, { "quit", pop3_quit, 0 }
, { "capa", pop3_capa, 0 }
, { "stls", pop3_stls, 0 }
, { "noop", okay, 0 }
, { 0, err_authoriz, 0 }
};

int main(argc,argv)
int argc;
char **argv;
{
  sig_alarmcatch(die);
  sig_pipeignore();
 
  hostname = argv[1];
  if (!hostname) die_usage();
  childargs = argv + 2;
  if (!*childargs) die_usage();

  if (env_get("UCSPITLS")) stls = 1;

  poplog_init(); 
  pop3_greet();
  commands(&ssin,pop3commands);
  die();
}
