#define main zimdb_core_main
#include "native_zone.cpp"
#undef main

int main(int argc, char** argv) {
    try {
        const auto start = Clock::now();
        Options options = parse_options(argc,argv);
        Image source(options.need("image"));
        fs::path out = options.need("out");
        require(!fs::exists(out),"reencode output exists");
        fs::create_directories(out.parent_path());
        fs::path temp = out.string()+".tmp";
        int fd = ::open(temp.c_str(),O_CREAT|O_EXCL|O_RDWR,0644);
        syscheck(fd>=0,"create reencode output");
        FILE* output = ::fdopen(fd,"w+b");
        syscheck(output,"fdopen reencode output");
        ImageHeader header = source.header();
        header.flags = (header.flags | kRrsetPageFlag | kCowIndexFlag) & ~(kPackedIndexFlag | kPoolFlag);
        std::string layout=options.get("page-layout","rrset");
        require(layout=="rrset"||layout=="columnar","invalid reencode page layout");
        if(layout=="columnar")header.flags=(header.flags|kColumnPageFlag)&~kNsec3NextKeyFlag;
        else header.flags&=~kColumnPageFlag;
        if(options.get("ns-templates","0")=="1"){
            require(layout=="columnar","NS templates require columnar pages");header.flags|=kNsTemplateFlag;
        }else header.flags&=~kNsTemplateFlag;
        if(options.get("nsec3-links","0")=="1"){
            require(header.flags&kNsTemplateFlag,"NSEC3 links require NS-template representation");header.flags|=kNsec3PageLinkFlag;
        }else header.flags&=~kNsec3PageLinkFlag;
        unsigned long pool_entries=std::stoul(options.get("ns-pool-entries","65536"));
        require(pool_entries<=65536,"invalid pool entry limit");
        std::unique_ptr<NsPoolBuilder> pool;
        if(pool_entries){pool=std::make_unique<NsPoolBuilder>(pool_entries);header.flags|=kNsPoolFlag;}
        else header.flags&=~kNsPoolFlag;
        write_all(output,&header,sizeof(header));
        CowStore store(output);
        CowSequenceBuilder builder(store);
        uint64_t decoded = 0, encoded = 0, rows = 0;
        for (uint64_t i = 0; i < source.header().page_count; ++i) {
            auto records = source.page(i);
            auto page = write_page_extent(output,records,header.flags,2,pool.get());
            decoded += page.decoded_size;
            encoded += page.encoded_size;
            rows += page.record_count;
            builder.add(page);
            if ((i+1)%50000 == 0)
                stage("reencode_progress",seconds_since(start),"\"pages\":"+std::to_string(i+1));
        }
        require(rows == header.unique_records,"reencode count mismatch");
        NsPoolMeta pool_meta{};
        if(pool)pool_meta=pool->write(output);
        store.snapshot(header,builder.finish());
        if(pool)std::memcpy(header.reserved+sizeof(CowIndexMeta),&pool_meta,sizeof(pool_meta));
        syscheck(::fseeko(output,0,SEEK_SET)==0,"seek reencode header");
        write_all(output,&header,sizeof(header));
        syscheck(std::fflush(output)==0 && ::fsync(fd)==0,"sync reencoded image");
        syscheck(std::fclose(output)==0,"close reencoded image");
        syscheck(::link(temp.c_str(),out.c_str())==0,"publish reencoded image");
        syscheck(::unlink(temp.c_str())==0,"unlink temp image");
        sync_directory(out.parent_path());
        std::cout << "{\"status\":\"P1_REENCODE_PENDING_FULL_VALIDATION\",\"source_image_bytes\":"
                  << source.committed_bytes() << ",\"image_bytes\":" << fs::file_size(out)
                  << ",\"decoded_page_bytes\":" << decoded << ",\"encoded_page_bytes\":" << encoded
                  << ",\"index_bytes\":" << store.created_bytes << ",\"unique_rrs\":" << rows
                  << ",\"ns_pool_entries\":" << pool_meta.entries << ",\"ns_pool_bytes\":" << pool_meta.stored_bytes
                  << ",\"page_layout\":" << json_string(layout)
                  << ",\"pages\":" << header.page_count << ",\"reencode_seconds_not_T_build\":"
                  << seconds_since(start) << "}\n";
    } catch (const std::exception& e) { std::cerr << "ERROR " << e.what() << '\n'; return 1; }
}
