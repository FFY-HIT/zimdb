/* Public domain. */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "seek.h"
#include "byte.h"
#include "cdb.h"
#include "inbuf.h"

void cdb_free(struct cdb *c)
{
  if (c->map) {
    munmap(c->map,c->size);
    c->map = 0;
  }
}

void cdb_findstart(struct cdb *c)
{
  c->loop = 0;
}

void cdb_init(struct cdb *c,num fd)
{
  struct stat st;
  char *x;

  cdb_free(c);
  cdb_findstart(c);
  c->fd = fd;

  if (fstat(fd,&st) == 0) {
    size_t s = st.st_size;
    if (s == st.st_size) {
      x = mmap(0,s,PROT_READ,MAP_SHARED,fd,0);
      if (x != (void *) (-1)) {
	c->size = st.st_size;
	c->map = x;
      }
    }
  }
}

num cdb_read(struct cdb *c,char *buf,num len,num pos)
{
  if (pos < 0) goto FORMAT;
  if (len < 0) goto FORMAT;
  if (c->map) {
    if ((pos > c->size) || (c->size - pos < len)) goto FORMAT;
    byte_copy(buf,len,c->map + pos);
  }
  else {
    if (seek_set(c->fd,pos) == -1) return -1;
    while (len > 0) {
      num r;
      do
        r = inbuf_unixread(c->fd,buf,len);
      while ((r == -1) && (errno == EINTR));
      if (r == -1) return -1;
      if (r == 0) goto FORMAT;
      buf += r;
      len -= r;
    }
  }
  return 0;

  FORMAT:
  errno = EPROTO;
  return -1;
}

static num match(struct cdb *c,const char *key,num len,num pos)
{
  char buf[32];
  num n;

  while (len > 0) {
    n = sizeof buf;
    if (n > len) n = len;
    if (cdb_read(c,buf,n,pos) == -1) return -1;
    if (byte_diff(buf,n,key)) return 0;
    pos += n;
    key += n;
    len -= n;
  }
  return 1;
}

num cdb_findnext(struct cdb *c,const char *key,num len)
{
  char buf[2*CDB_NUMBYTES];
  num pos;
  num u;

  if (!c->loop) {
    u = cdb_hash(key,len);
    if (cdb_read(c,buf,2*CDB_NUMBYTES,(u*2*CDB_NUMBYTES) & (256*2*CDB_NUMBYTES-1)) == -1) return -1;
    c->hslots = cdb_unpacknum(buf+CDB_NUMBYTES);
    if (c->hslots <= 0) return 0;
    c->hpos = cdb_unpacknum(buf);
    c->khash = u;
    u = CDB_HASHTOP(u);
    u %= c->hslots;
    u *= 2*CDB_NUMBYTES;
    c->kpos = c->hpos + u;
  }

  while (c->loop < c->hslots) {
    if (cdb_read(c,buf,2*CDB_NUMBYTES,c->kpos) == -1) return -1;
    pos = cdb_unpacknum(buf+CDB_NUMBYTES);
    if (pos <= 0) return 0;
    c->loop += 1;
    c->kpos += 2*CDB_NUMBYTES;
    if (c->kpos == c->hpos + (c->hslots * 2*CDB_NUMBYTES)) c->kpos = c->hpos;
    u = cdb_unpacknum(buf);
    if (u == c->khash) {
      if (cdb_read(c,buf,2*CDB_NUMBYTES,pos) == -1) return -1;
      u = cdb_unpacknum(buf);
      if (u == len)
	switch(match(c,key,len,pos + 2*CDB_NUMBYTES)) {
	  case -1:
	    return -1;
	  case 1:
	    c->dlen = cdb_unpacknum(buf+CDB_NUMBYTES);
	    c->dpos = pos + 2*CDB_NUMBYTES + len;
	    return 1;
	}
    }
  }

  return 0;
}

num cdb_find(struct cdb *c,const char *key,num len)
{
  cdb_findstart(c);
  return cdb_findnext(c,key,len);
}
