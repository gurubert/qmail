#ifndef IPME_H
#define IPME_H

#include "ip.h"
#include "ipalloc.h"

extern ipalloc ipme;

extern int ipme_init();
extern int ipme_is();
#ifdef INET6
extern int ipme_is46();
#endif

#endif
