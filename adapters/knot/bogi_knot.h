#pragma once

#include "knot/zone/contents.h"
#include "libknot/dname.h"
#include "libknot/packet/pkt.h"
#include "knot/nameserver/process_query.h"

void bogi_knot_open_all(void);
void bogi_knot_close_all(void);

/* Kept for process_query hook; always returns 0 (Answer short-circuit disabled). */
int bogi_knot_try_answer(knot_pkt_t *pkt, knotd_qdata_t *qdata);

/* Replace stub zone contents with Dig apex SOA+NS when env matches. */
int bogi_knot_seed_contents(zone_contents_t **contents, const knot_dname_t *zone_name);

void bogi_knot_lazy_lookup(zone_contents_t *contents, const knot_dname_t *qname);
void bogi_knot_lazy_rrset(const zone_node_t *node, uint16_t type);
int bogi_knot_hydrate_depth(void);

void bogi_knot_release_contents(zone_contents_t **contents, const knot_dname_t *zone_name);
