#include "num.h"

num num_from8bytes(const char *s)
{
  num result;

  result  = (unsigned char) s[7]; result <<= 8;
  result += (unsigned char) s[6]; result <<= 8;
  result += (unsigned char) s[5]; result <<= 8;
  result += (unsigned char) s[4]; result <<= 8;
  result += (unsigned char) s[3]; result <<= 8;
  result += (unsigned char) s[2]; result <<= 8;
  result += (unsigned char) s[1]; result <<= 8;
  result += (unsigned char) s[0];
  return result;
}
