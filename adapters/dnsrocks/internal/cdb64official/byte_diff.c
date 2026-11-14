#include "byte.h"

num byte_diff(const char *s,num n,const char *t)
{
  for (;;) {
    if (!n) return 0;
    if (*s != *t) break;
    ++s; ++t; --n;
    if (!n) return 0;
    if (*s != *t) break;
    ++s; ++t; --n;
    if (!n) return 0;
    if (*s != *t) break;
    ++s; ++t; --n;
    if (!n) return 0;
    if (*s != *t) break;
    ++s; ++t; --n;
  }
  return ((int)(unsigned int)(unsigned char) *s)
       - ((int)(unsigned int)(unsigned char) *t);
}
