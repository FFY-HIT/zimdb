#ifndef BOGI_AUTH_ANSWER_H
#define BOGI_AUTH_ANSWER_H

#include <stddef.h>
#include <stdint.h>

#include "bogi23_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BogiAuthCtx {
	Bogi23Reader reader;
	int open;
} BogiAuthCtx;

int bogi_auth_open(BogiAuthCtx *ctx, const char *image_path);
void bogi_auth_close(BogiAuthCtx *ctx);

int bogi_auth_answer_query(BogiAuthCtx *ctx,
			   const uint8_t *query_wire, size_t query_len,
			   uint8_t *out_buf, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
