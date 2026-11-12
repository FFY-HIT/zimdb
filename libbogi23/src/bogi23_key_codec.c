#include "bogi23_key_codec.h"
#include <errno.h>
#include <limits.h>
#include <lz4.h>
#include <snappy-c.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define KC_BUCKETS 1024u
#define KC_OWNERS 16u

typedef struct KeyEntry {
    uint64_t ordinal, length, charge;
    struct KeyEntry *hash_next, *older, *newer;
    const uint8_t *data;
    uint8_t bytes[];
} KeyEntry;

typedef struct {
    uint64_t logical, physical, stored, raw, key_physical, ordinal;
    uint32_t key_length, codec, owners, crc;
} KeyDesc;

typedef struct {
    uint64_t logical, physical, raw, stored, ordinal;
    uint32_t codec, crc;
    unsigned crc_verified;
} KeyFrame;

typedef struct {
    uint64_t logical_size, prefix_len, suffix_logical, suffix_len;
    uint64_t prefix_phys, containers_phys, directory_phys, count;
    uint64_t keys_phys, keys_len, suffix_phys, owner_count;
    uint32_t codec;
    size_t cache_limit, cache_charge;
    KeyEntry **buckets, *newest, *oldest;
    uint64_t entries;
    uint64_t current_group;
    unsigned current_valid, current_owners;
    KeyFrame frame[KC_OWNERS];
    uint64_t reads, hits, misses, snappy, lz4, decoded, compressed;
    uint64_t container_checks, frame_checks, max_raw, group_scans, plain_reads;
} KeyState;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | ((uint64_t)le32(p+4) << 32); }
static int span(uint64_t start, uint64_t size, uint64_t limit) {
    return start <= limit && size <= limit-start;
}
static int codec_ok(uint32_t c) { return c==0u || c==1u || c==4u; }

static uint32_t checksum(const uint8_t *p, uint64_t length) {
    uLong crc=crc32(0L,Z_NULL,0);
    while (length) {
        uInt part=length>UINT_MAX ? UINT_MAX : (uInt)length;
        crc=crc32(crc,p,part); p+=part; length-=part;
    }
    return (uint32_t)crc;
}

static int uleb(const uint8_t **p, const uint8_t *end, uint64_t *answer) {
    uint64_t value=0u;
    unsigned i;
    for(i=0u;i<10u;i++) {
        uint8_t b;
        if(*p>=end) return -1;
        b=*(*p)++;
        if(i==9u && (b&0xfeu)) return -1;
        value|=(uint64_t)(b&127u)<<(7u*i);
        if(!(b&128u)) {
            if(i && !b) return -1;
            *answer=value; return 0;
        }
    }
    return -1;
}

static int budget(size_t *out) {
    const char *value=getenv("ZIMDB_KEY_CACHE_BYTES");
    char *end;
    unsigned long long number;
    if(!value) value=getenv("ZIMDB_BLOCK_CACHE_BYTES");
    if(!value) { *out=8u*1024u*1024u; return 0; }
    if(!*value || *value=='-') return -1;
    errno=0; number=strtoull(value,&end,10);
    if(errno || *end || number>SIZE_MAX) return -1;
    *out=(size_t)number; return 0;
}

int bogi23_key_attach(Bogi23Reader *reader) {
    const uint8_t *p=reader->map_base;
    uint64_t f[14], bytes, owners;
    KeyState *s;
    size_t i;
    if(reader->map_size<8u || memcmp(p,BOGI23_KEY_MAGIC,8u)) return 0;
    if(reader->map_size<128u || le16(p+8)!=2u || le16(p+10)!=128u || !codec_ok(le32(p+12))) return -1;
    for(i=0;i<14u;i++) f[i]=le64(p+16u+8u*i);
    if(f[7]>UINT64_MAX/64u) return -1;
    bytes=f[7]*64u;
    if(f[0]<128u || f[1]<128u || f[2]<=f[1] || f[2]>f[0] || f[3]!=f[0]-f[2] ||
       f[4]!=128u || !span(f[4],f[1],reader->map_size) || f[5]!=f[4]+f[1] ||
       f[6]<f[5] || !f[7] || !span(f[6],bytes,reader->map_size) ||
       f[8]!=f[6]+bytes || !span(f[8],f[9],reader->map_size) ||
       f[10]!=f[8]+f[9] || !span(f[10],f[3],reader->map_size) ||
       f[11]!=f[10]+f[3] || f[11]!=reader->map_size || f[12]!=ZIR3_PROFILE_DNSSEC || f[13]!=1u) return -1;
    p=reader->map_base+(size_t)f[4];
    owners=le64(p+88);
    if(memcmp(p,ZIR3_BOGI_MAGIC,8u) || le64(p+32)!=f[0] || le64(p+64)!=f[7] ||
       le64(p+72)!=f[1] || le64(p+80)!=f[2]-f[1] || le32(p+20)!=f[12] ||
       (le32(p+24)&~ZIR3_FLAG_BINARY_POOL) || !owners ||
       owners/KC_OWNERS+(owners%KC_OWNERS!=0u)!=f[7]) return -1;
    s=(KeyState *)calloc(1,sizeof(*s));
    if(!s) return -1;
    s->logical_size=f[0]; s->prefix_len=f[1]; s->suffix_logical=f[2]; s->suffix_len=f[3];
    s->prefix_phys=f[4]; s->containers_phys=f[5]; s->directory_phys=f[6]; s->count=f[7];
    s->keys_phys=f[8]; s->keys_len=f[9]; s->suffix_phys=f[10]; s->owner_count=owners;
    s->codec=le32(reader->map_base+12);
    if(budget(&s->cache_limit)) { free(s); return -1; }
    reader->key_codec=s;
    return 1;
}

uint64_t bogi23_key_logical_size(const Bogi23Reader *reader) {
    const KeyState *s=(const KeyState *)reader->key_codec;
    return s ? s->logical_size : reader->map_size;
}

static int desc(Bogi23Reader *reader, uint64_t number, KeyDesc *d) {
    KeyState *s=(KeyState *)reader->key_codec;
    const uint8_t *p;
    uint64_t expected,next,restart_off,relative;
    if(!s || number>=s->count) return -1;
    p=reader->map_base+(size_t)(s->directory_phys+number*64u);
    d->logical=le64(p); d->physical=le64(p+8); d->stored=le64(p+16); d->raw=le64(p+24);
    d->key_physical=le64(p+32); d->ordinal=le64(p+40); d->key_length=le32(p+48);
    d->codec=le32(p+52); d->owners=le32(p+56); d->crc=le32(p+60);
    if(number>UINT64_MAX/KC_OWNERS || d->ordinal!=number*KC_OWNERS || d->ordinal>=s->owner_count) return -1;
    expected=s->owner_count-d->ordinal; if(expected>KC_OWNERS) expected=KC_OWNERS;
    if(d->owners!=expected || d->codec!=s->codec || !d->raw || !d->stored ||
       d->logical<s->prefix_len || !span(d->logical,d->raw,s->suffix_logical) ||
       d->physical<s->containers_phys || !span(d->physical,d->stored,s->directory_phys) ||
       d->key_length>ZIR3_MAX_KEY || d->key_physical<s->keys_phys ||
       !span(d->key_physical,d->key_length,s->keys_phys+s->keys_len)) return -1;
    if(number==0u && (d->logical!=s->prefix_len || d->physical!=s->containers_phys)) return -1;
    next=number+1u==s->count ? s->suffix_logical : le64(p+64u);
    if(d->logical+d->raw!=next) return -1;
    next=number+1u==s->count ? s->directory_phys : le64(p+64u+8u);
    if(d->physical+d->stored!=next) return -1;
    restart_off=le64(reader->map_base+(size_t)s->prefix_phys+56u);
    if(!span(restart_off,8u*s->count,s->prefix_len)) return -1;
    relative=le64(reader->map_base+(size_t)(s->prefix_phys+restart_off+number*8u));
    if(relative!=d->logical-s->prefix_len) return -1;
    return 0;
}

int bogi23_key_first_key(Bogi23Reader *reader, uint64_t number, uint8_t *key, size_t *length) {
    KeyDesc d;
    if(desc(reader,number,&d)) return -1;
    if(d.key_length) memcpy(key,reader->map_base+(size_t)d.key_physical,d.key_length);
    *length=d.key_length;
    return 0;
}

static int load_group(Bogi23Reader *reader, uint64_t number, const KeyDesc *d) {
    KeyState *s=(KeyState *)reader->key_codec;
    const uint8_t *begin=reader->map_base+(size_t)d->physical;
    const uint8_t *p=begin,*end=begin+(size_t)d->stored;
    uint64_t logical=d->logical;
    unsigned i;
    if(s->current_valid && s->current_group==number) return 0;
    s->current_valid=0;
    s->container_checks++;
    if(checksum(begin,d->stored)!=d->crc) return -1;
    for(i=0;i<d->owners;i++) {
        KeyFrame *f=&s->frame[i];
        if(uleb(&p,end,&f->raw) || uleb(&p,end,&f->stored) || (uint64_t)(end-p)<5u) return -1;
        f->codec=*p++; f->crc=le32(p); p+=4;
        if(!f->raw || !f->stored || !codec_ok(f->codec) || (f->codec && f->codec!=s->codec) ||
           f->stored>(uint64_t)(end-p) || f->raw>d->logical+d->raw-logical ||
           f->raw>SIZE_MAX || f->stored>SIZE_MAX ||
           (f->codec && f->raw>BOGI23_KEY_COMPRESSED_RAW_LIMIT) ||
           (!f->codec && f->stored!=f->raw)) return -1;
        f->logical=logical; f->physical=(uint64_t)(p-reader->map_base);
        f->ordinal=d->ordinal+i; f->crc_verified=0;
        logical+=f->raw; p+=(size_t)f->stored;
    }
    if(p!=end || logical!=d->logical+d->raw) return -1;
    s->current_group=number; s->current_owners=d->owners; s->current_valid=1;
    s->group_scans++;
    return 0;
}

static int locate(Bogi23Reader *reader, uint64_t offset, KeyFrame **frame) {
    KeyState *s=(KeyState *)reader->key_codec;
    KeyDesc d;
    uint64_t low=0u,high=s->count,number;
    unsigned i;
    if(s->current_valid && offset>=s->frame[0].logical &&
       offset-s->frame[0].logical<s->frame[s->current_owners-1u].logical+s->frame[s->current_owners-1u].raw-s->frame[0].logical) {
        for(i=0;i<s->current_owners;i++) if(offset>=s->frame[i].logical && offset-s->frame[i].logical<s->frame[i].raw) {
            *frame=&s->frame[i]; return 0;
        }
    }
    while(low<high) {
        uint64_t middle=low+(high-low)/2u;
        const uint8_t *p=reader->map_base+(size_t)(s->directory_phys+middle*64u);
        if(le64(p)<=offset) low=middle+1u; else high=middle;
    }
    if(!low) return -1;
    number=low-1u;
    if(desc(reader,number,&d) || offset<d.logical || offset-d.logical>=d.raw || load_group(reader,number,&d)) return -1;
    for(i=0;i<s->current_owners;i++) if(offset>=s->frame[i].logical && offset-s->frame[i].logical<s->frame[i].raw) {
        *frame=&s->frame[i]; return 0;
    }
    return -1;
}

static void unlink_lru(KeyState *s,KeyEntry *e) {
    if(e->older) e->older->newer=e->newer; else s->oldest=e->newer;
    if(e->newer) e->newer->older=e->older; else s->newest=e->older;
}
static void newest(KeyState *s,KeyEntry *e) {
    e->newer=NULL; e->older=s->newest;
    if(s->newest) s->newest->newer=e; else s->oldest=e;
    s->newest=e;
}
static void evict(KeyState *s) {
    KeyEntry *e=s->oldest,**link;
    if(!e) return;
    link=&s->buckets[e->ordinal%KC_BUCKETS];
    while(*link && *link!=e) link=&(*link)->hash_next;
    if(*link) *link=e->hash_next;
    unlink_lru(s,e); s->cache_charge-=(size_t)e->charge; s->entries--; free(e);
}
static KeyEntry *cached(KeyState *s,uint64_t ordinal) {
    KeyEntry *e;
    if(!s->buckets) return NULL;
    for(e=s->buckets[ordinal%KC_BUCKETS];e;e=e->hash_next) if(e->ordinal==ordinal) return e;
    return NULL;
}

static KeyEntry *fetch(Bogi23Reader *reader,KeyFrame *f,int *retained) {
    KeyState *s=(KeyState *)reader->key_codec;
    const uint8_t *input=reader->map_base+(size_t)f->physical;
    size_t length=(size_t)f->stored,raw=(size_t)f->raw;
    KeyEntry *e=cached(s,f->ordinal);
    *retained=0; s->reads++;
    if(e) { s->hits++; unlink_lru(s,e); newest(s,e); *retained=1; return e; }
    s->misses++;
    if(raw>SIZE_MAX-sizeof(*e)) return NULL;
    e=(KeyEntry *)malloc(sizeof(*e)+(f->codec ? raw : 0u));
    if(!e) return NULL;
    memset(e,0,sizeof(*e)); e->ordinal=f->ordinal; e->length=raw; e->charge=sizeof(*e)+raw;
    e->data=f->codec ? e->bytes : input;
    if(f->codec==1u) {
        size_t expected=0u,decoded=raw;
        if(snappy_uncompressed_length((const char *)input,length,&expected)!=SNAPPY_OK || expected!=raw ||
           snappy_uncompress((const char *)input,length,(char *)e->bytes,&decoded)!=SNAPPY_OK || decoded!=raw) goto fail;
        s->snappy++; s->decoded+=raw; s->compressed+=length;
    } else if(f->codec==4u) {
        const uint8_t *end=input+length;
        uint64_t expected;
        if(uleb(&input,end,&expected) || expected!=raw || (uint64_t)(end-input)>INT_MAX || raw>INT_MAX ||
           LZ4_decompress_safe((const char *)input,(char *)e->bytes,(int)(end-input),(int)raw)!=(int)raw) goto fail;
        s->lz4++; s->decoded+=raw; s->compressed+=f->stored;
    } else s->plain_reads++;
    if(!f->crc_verified) {
        s->frame_checks++;
        if(checksum(e->data,raw)!=f->crc) goto fail;
        f->crc_verified=1;
    }
    if(raw>s->max_raw) s->max_raw=raw;
    if(!s->buckets && s->cache_limit>=KC_BUCKETS*sizeof(KeyEntry *) &&
       e->charge<=s->cache_limit-KC_BUCKETS*sizeof(KeyEntry *)) {
        s->buckets=(KeyEntry **)calloc(KC_BUCKETS,sizeof(KeyEntry *));
        if(s->buckets) s->cache_charge=KC_BUCKETS*sizeof(KeyEntry *);
    }
    if(s->buckets && e->charge<=s->cache_limit-KC_BUCKETS*sizeof(KeyEntry *)) {
        while(s->oldest && e->charge>s->cache_limit-s->cache_charge) evict(s);
        if(e->charge<=s->cache_limit-s->cache_charge) {
            e->hash_next=s->buckets[e->ordinal%KC_BUCKETS]; s->buckets[e->ordinal%KC_BUCKETS]=e;
            newest(s,e); s->cache_charge+=(size_t)e->charge; s->entries++; *retained=1;
        }
    }
    return e;
fail:
    free(e); return NULL;
}

int bogi23_key_read(Bogi23Reader *reader,uint64_t offset,uint64_t length,void *out) {
    KeyState *s=(KeyState *)reader->key_codec;
    uint8_t *destination=(uint8_t *)out;
    if(!s || length>SIZE_MAX || !span(offset,length,s->logical_size)) return -1;
    while(length) {
        uint64_t amount;
        if(offset<s->prefix_len) {
            amount=s->prefix_len-offset; if(amount>length) amount=length;
            memcpy(destination,reader->map_base+(size_t)(s->prefix_phys+offset),(size_t)amount);
        } else if(offset>=s->suffix_logical) {
            amount=length;
            memcpy(destination,reader->map_base+(size_t)(s->suffix_phys+offset-s->suffix_logical),(size_t)amount);
        } else {
            KeyFrame *frame; KeyEntry *e; int retained;
            if(locate(reader,offset,&frame)) return -1;
            amount=frame->raw-(offset-frame->logical); if(amount>length) amount=length;
            e=fetch(reader,frame,&retained); if(!e) return -1;
            memcpy(destination,e->data+(size_t)(offset-frame->logical),(size_t)amount);
            if(!retained) free(e);
        }
        destination+=(size_t)amount; offset+=amount; length-=amount;
    }
    return 0;
}

void bogi23_key_close(Bogi23Reader *reader) {
    KeyState *s=(KeyState *)reader->key_codec;
    if(!s) return;
    while(s->oldest) evict(s);
    free(s->buckets); free(s); reader->key_codec=NULL;
}

int bogi23_key_stats(const Bogi23Reader *reader,uint64_t v[18]) {
    const KeyState *s=(const KeyState *)reader->key_codec;
    if(!s) { memset(v,0,18u*sizeof(*v)); return 0; }
    v[0]=s->count; v[1]=s->owner_count; v[2]=s->reads; v[3]=s->hits; v[4]=s->misses;
    v[5]=s->snappy; v[6]=s->lz4; v[7]=s->decoded; v[8]=s->compressed;
    v[9]=s->container_checks; v[10]=s->frame_checks; v[11]=s->cache_charge; v[12]=s->cache_limit;
    v[13]=s->entries; v[14]=s->max_raw; v[15]=s->codec; v[16]=s->group_scans; v[17]=s->plain_reads;
    return 1;
}
