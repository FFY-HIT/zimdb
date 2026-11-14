#ifndef num_h
#define num_h

typedef long long num;

extern num num_from4bytes(const char *);
extern num num_from8bytes(const char *);

extern num num_fromstring_allowoverflow(const char *);

extern num num_tostring_nonneg(char *,num);
#define NUM_TOSTRING_NONNEG 40 /* enough space to hold 2^128 - 1 in decimal, plus \0 */

extern void num_to4bytes_allowoverflow(char *,num);
extern void num_to8bytes_allowoverflow(char *,num);

#endif
