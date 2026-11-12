#include "bogi23_reader.h"
#include "bogi23_export.h"
#include "bogi23_key_codec.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int stats(const Bogi23Reader *reader) {
    uint64_t v[18];
    int wrapped=bogi23_key_stats(reader,v);
    printf("{\"wrapped\":%d,\"logical_size\":%" PRIu64 ",\"values\":[",wrapped,reader->file_size);
    for(unsigned i=0;i<18;i++) printf("%s%" PRIu64,i?",":"",v[i]);
    puts("]}");
    return 0;
}

int main(int argc,char **argv) {
    Bogi23Reader reader;
    int rc=0;
    if(argc<3) { fprintf(stderr,"usage: keycodec_smoke stats|readback|lookup image [path|owner]\n"); return 2; }
    if(bogi23_open(&reader,argv[2])) { fprintf(stderr,"open failed\n"); return 3; }
    if(!strcmp(argv[1],"stats")) {
        uint64_t before[18],after[18];
        uint8_t key[ZIR3_MAX_KEY]; size_t length;
        bogi23_key_stats(&reader,before);
        if(reader.key_codec && (bogi23_key_first_key(&reader,0,key,&length) ||
           bogi23_key_first_key(&reader,reader.owner_restart_count-1,key,&length))) rc=4;
        bogi23_key_stats(&reader,after);
        if(after[5] || after[6] || after[11] || before[5] || before[6]) rc=5;
        stats(&reader);
    } else if(!strcmp(argv[1],"readback") && argc==4) {
        uint8_t buffer[65553];
        uint64_t offset=0;
        FILE *file=fopen(argv[3],"wb");
        if(!file) rc=6;
        while(!rc && offset<reader.file_size) {
            uint64_t n=reader.file_size-offset;
            if(n>sizeof(buffer)) n=sizeof(buffer);
            if(bogi23_read_logical(&reader,offset,n,buffer) || fwrite(buffer,1,(size_t)n,file)!=(size_t)n) rc=7;
            offset+=n;
        }
        if(file && fclose(file)) rc=8;
        if(!bogi23_read_logical(&reader,reader.file_size,1,buffer) ||
           !bogi23_read_logical(&reader,UINT64_MAX,1,buffer)) rc=9;
        stats(&reader);
    } else if(!strcmp(argv[1],"lookup") && argc==4) {
        for(unsigned i=0;i<2u;i++) {
            Bogi23OwnerGroup group;
            int found=0;
            if(bogi23_trace_begin(&reader)) { rc=10; break; }
            if(bogi23_lookup_group(&reader,argv[3],&group,&found)) rc=11;
            else {
                printf("{\"lookup\":%u,\"found\":%d,\"rrsets\":%zu}\n",i,found,found?group.count:0u);
                if(found) bogi23_free_group(&reader,&group);
            }
            bogi23_trace_end(&reader);
            if(rc) break;
        }
        stats(&reader);
    } else rc=2;
    bogi23_close(&reader);
    return rc;
}
