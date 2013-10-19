#ifndef SMTPDLOG_H
#define SMTPDLOG_H
#define FDLOG 2

void flush();
void out();

void smtp_loga();
void smtp_logt();
void smtp_logg();
void smtp_logi();

void die_read();
void die_alarm();
void die_nomem();
void die_control();
void die_ipme();
void die_starttls();
void die_recipients();
void straynewline();

void err_unimpl();
void err_syntax();
void err_notorious();
void err_noop();
void err_vrfy();
void err_qqt();

int err_child();
int err_fork();
int err_pipe();
int err_write();
int err_starttls();
void err_tlsreq();

void err_helo();

void err_authd();
void err_authmail(); 
void err_authfail();
void err_authreq();
void err_submission();
int err_noauth();
int err_authabrt();
int err_input(); 

void err_wantmail();
void err_mav();
void err_bmf();
void err_mfdns();

void err_nogateway();
void err_brt();
void err_rcpts();
void err_recipient();

void straynewline(); 
void err_notorious();
void err_size(void);
void err_data();

void err_nullrcpt();

#endif
