#ifndef ZIR3_BOGI23_BINARY_POOL_H
#define ZIR3_BOGI23_BINARY_POOL_H

#include <stddef.h>
#include <stdint.h>

/* Expand a tagged binary pool payload to a malloc'd presentation string.
 * Caller frees with free(). Returns 0 on success.
 */
int bogi23_binary_pool_expand(const uint8_t *payload, size_t length, char **out);

#endif
