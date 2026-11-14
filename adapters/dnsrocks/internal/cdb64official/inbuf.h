#ifndef inbuf_h
#define inbuf_h

#include "num.h"

extern num inbuf_unixread(num,char *,num);

typedef struct inbuf {
  char *x;
  num p;
  num n;
  num fd;
  num (*op)(num,char *,num);
} inbuf;

#define INBUF_INIT(op,fd,buf,len) { (buf), 0, (len), (fd), (op) }
#define INBUF_SIZE 8192

extern void inbuf_init(inbuf *,num (*)(num,char *,num),num,char *,num);

extern num inbuf_get(inbuf *,char *,num);
extern num inbuf_feed(inbuf *);

extern char *inbuf_peek(inbuf *);
extern void inbuf_seek(inbuf *,num);

#define inbuf_PEEK(s) ( (s)->x + (s)->n )
#define inbuf_SEEK(s,len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

#define inbuf_GETC(s,c) \
  ( ((s)->p > 0) \
    ? ( *(c) = (s)->x[(s)->n], inbuf_SEEK((s),1), 1 ) \
    : inbuf_get((s),(c),1) \
  )

extern inbuf *inbuf_0;

#endif
