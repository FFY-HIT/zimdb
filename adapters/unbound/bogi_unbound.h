#ifndef BOGI_UNBOUND_H
#define BOGI_UNBOUND_H
struct sldns_buffer;
struct auth_zones;
struct query_info;
void bogi_unbound_open_all(void);
void bogi_unbound_close_all(void);
/* Dig hydrate into auth-zone; always returns 0 so native Auth continues. */
int bogi_unbound_try_answer(struct sldns_buffer *buf);
void bogi_unbound_lazy(struct auth_zones *az, struct query_info *qinfo);
void bogi_unbound_release(struct auth_zones *az);
#endif
