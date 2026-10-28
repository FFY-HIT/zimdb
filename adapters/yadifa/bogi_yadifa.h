#ifndef BOGI_YADIFA_H
#define BOGI_YADIFA_H
#include <dnscore/dns_message.h>
void bogi_yadifa_open_all(void);
void bogi_yadifa_close_all(void);
int bogi_yadifa_try_answer(dns_message_t *mesg);
/* Dig hydrate before native database_query; always return so caller continues. */
void bogi_yadifa_lazy(dns_message_t *mesg);
#endif
