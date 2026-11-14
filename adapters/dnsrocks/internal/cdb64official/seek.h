#ifndef SEEK_H
#define SEEK_H

#include "num.h"

extern num seek_cur(num);

extern num seek_set(num,num);

#define seek_begin(fd) (seek_set((fd),0))

#endif
