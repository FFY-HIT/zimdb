#include <unistd.h>
#include <sys/types.h>
#include "seek.h"

num seek_set(num fd,num pos)
{ if (lseek(fd,(off_t) pos,SEEK_SET) == -1) return -1; return 0; }
