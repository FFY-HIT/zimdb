#define main zimdb_core_main
#include "native_zone.cpp"
#undef main

int main(int argc,char**argv){
    try{
        require(argc==2,"usage: column_accounting full_image");Image image(argv[1]);
        require(image.header().flags&kColumnPageFlag,"column image required");
        FILE*input=std::fopen(argv[1],"rb");syscheck(input,"open accounting image");
        std::array<uint64_t,5>raw{},stored{};uint64_t pages_bytes=0,headers_bytes=0,maximum_raw_page=0;
        for(uint64_t i=0;i<image.header().page_count;++i){
            auto page=image.index(i);require(page.codec==0&&page.encoded_size<=kMaxPage,"unexpected column outer codec");
            Bytes container(page.encoded_size);syscheck(::fseeko(input,page.offset,SEEK_SET)==0,"seek accounting page");
            require(std::fread(container.data(),1,container.size(),input)==container.size(),"truncated accounting page");
            require(checksum(container.data(),container.size())==page.checksum,"accounting page checksum mismatch");
            size_t p=0;uint32_t magic=get32(container.data(),container.size(),p);
            require(magic==0x314c435aU||magic==0x324c435aU||magic==0x334c435aU,"unexpected accounting page format");
            for(int j=0;j<3;++j)(void)get32(container.data(),container.size(),p);
            uint64_t raw_page=0,stored_page=0;
            for(size_t j=0;j<5;++j){
                auto r=get32(container.data(),container.size(),p),s=get32(container.data(),container.size(),p),codec=get32(container.data(),container.size(),p);
                (void)get64(container.data(),container.size(),p);
                require(codec==0||codec==2,"unexpected component codec");
                if(j==4)require(codec==0&&r==s,"opaque field codec changed");
                raw[j]+=r;stored[j]+=s;raw_page+=r;stored_page+=s;
            }
            require(p+stored_page==container.size()&&raw_page<=kMaxPage,"accounting component bounds mismatch");
            maximum_raw_page=std::max(maximum_raw_page,raw_page);pages_bytes+=container.size();headers_bytes+=p;
        }
        std::fclose(input);
        std::array<const char*,5>names{{"owner_keys","ns_refs","rr_metadata","residual_payload","signature_and_ds_literals"}};
        std::cout<<"{\"status\":\"PASS_FORMAT_ACCOUNTING\",\"scope\":\"complete image component byte accounting; not a universal entropy lower bound\",\"image_bytes\":"<<image.committed_bytes()
                 <<",\"page_bytes\":"<<pages_bytes<<",\"page_header_bytes\":"<<headers_bytes
                 <<",\"maximum_raw_page_bytes\":"<<maximum_raw_page<<",\"nonpage_bytes\":"<<image.committed_bytes()-pages_bytes<<",\"components\":[";
        for(size_t j=0;j<5;++j){if(j)std::cout<<',';std::cout<<"{\"name\":"<<json_string(names[j])<<",\"raw_bytes\":"<<raw[j]<<",\"stored_bytes\":"<<stored[j]<<'}';}
        std::cout<<"]}\n";
    }catch(const std::exception&e){std::cerr<<"ERROR "<<e.what()<<'\n';return 1;}
}
