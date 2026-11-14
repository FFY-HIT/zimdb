#include <unistd.h>
#include "inbuf.h"

num inbuf_unixread(num fd,char *x,num len)
{
  if (len > 16777216) len = 16777216;
  return read(fd,x,len);
}
