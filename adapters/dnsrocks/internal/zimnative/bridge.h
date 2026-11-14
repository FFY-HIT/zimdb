#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void *zim_open(const char *path);
void zim_close(void *handle);
const char *zim_origin(void *handle);
unsigned char *zim_lookup(void *,const char *,size_t *,int *);
int zim_inspect_wire(void *,const unsigned char *,size_t,int);
unsigned char *zim_lookup_wire(void *,const unsigned char *,size_t,int,const uint16_t *,size_t,size_t *,int *);
#ifdef __cplusplus
}
#endif
