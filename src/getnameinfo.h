#ifndef JUICE_GETNAMEINFO_H
#define JUICE_GETNAMEINFO_H

#include <lwip/netdb.h>
#include <lwip/ip_addr.h>

/*
 * Constants for getnameinfo()
 */
#define    NI_MAXHOST  1025
#define    NI_MAXSERV  32

/*
 * Flag values for getnameinfo()
 */
#define    NI_NOFQDN   0x00000001
#define    NI_NUMERICHOST  0x00000002
#define    NI_NAMEREQD 0x00000004
#define    NI_NUMERICSERV  0x00000008
#define    NI_DGRAM    0x00000010
#define NI_WITHSCOPEID 0x00000020

int
getnameinfo(const struct sockaddr *sa, socklen_t salen,
           char *host, size_t hostlen,
           char *serv, size_t servlen, int flags);

#endif
