#ifndef BOGI_NSD_H
#define BOGI_NSD_H

#include <stdint.h>

struct nsd;
struct query;
struct zone;
struct namedb;
struct domain;
struct dname;

void bogi_nsd_open_all(struct nsd *nsd);
void bogi_nsd_close_all(void);
int bogi_nsd_try_answer(struct nsd *nsd, struct query *q);

int bogi_nsd_seed_zone(struct nsd *nsd, struct zone *zone, const char *bogi_path);
void bogi_nsd_lazy_lookup(struct namedb *db, const struct dname *qname);
void bogi_nsd_lazy_rrset(struct namedb *db, struct domain *domain,
                         struct zone *zone, uint16_t type);
int bogi_nsd_hydrate_depth(void);
/* After answering: drop hydrated RRs, keep apex SOA/NS seed only. */
void bogi_nsd_release_zone(struct zone *zone);

#endif
