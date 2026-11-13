// Bounded normalization of flattened CZDS RR streams. Every output remains a
// complete canonical wire RR. Unsupported records use the ordinary ldns codec.
void read_flat_zone(const std::string& path,const std::string& origin_text,
                    const std::function<void(const std::string&)>& consume) {
    struct Slot { uint16_t text_length=0,wire_length=0; std::array<char,256> text{},wire{}; };
    std::vector<Slot> cache(8192);
    size_t cached_bytes=0;
    FILE* input=std::fopen(path.c_str(),"rb");syscheck(input,"open flattened source");
    std::setvbuf(input,nullptr,_IOFBF,65536);
    ldns_rdf* origin=ldns_dname_new_frm_str(origin_text.c_str());
    ldns_rdf* previous=nullptr;
    require(origin,"invalid flat origin");
    std::vector<char> line_storage(1024*1024+1);
    std::array<char,65536> read_buffer{};
    size_t read_position=0,read_size=0;
    char* line=line_storage.data();
    auto bounded_line=[&]()->size_t{
        size_t length=0;
        while(true){
            if(read_position==read_size){read_size=std::fread(read_buffer.data(),1,read_buffer.size(),input);read_position=0;
                if(!read_size){require(!std::ferror(input),"flat source read failed");line[length]=0;return length;}}
            const char* first=read_buffer.data()+read_position;
            const void* found=std::memchr(first,'\n',read_size-read_position);
            size_t bytes=found?static_cast<const char*>(found)-first+1:read_size-read_position;
            require(bytes<=1024*1024-length,"flat record line exceeds declared bound");
            require(!std::memchr(first,0,bytes),"NUL byte in flattened source");
            std::memcpy(line+length,first,bytes);length+=bytes;read_position+=bytes;
            if(found){line[length]=0;return length;}
        }
    };
    uint64_t rows=0,hits=0,misses=0,fallbacks=0;
    std::string previous_text,owner_wire;
    auto equal_ascii=[](std::string_view a,std::string_view b){
        if(a.size()!=b.size())return false;
        for(size_t i=0;i<a.size();++i){unsigned x=static_cast<unsigned char>(a[i]);
            if(x>='a'&&x<='z')x-=32;
            if(x!=static_cast<unsigned char>(b[i]))return false;}
        return true;
    };
    auto plain_name=[](std::string_view name){
        return name.size()<=255 && std::all_of(name.begin(),name.end(),[](unsigned char c){
            return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_'||c=='*';
        });
    };
    try {
        while(true){
            size_t length=bounded_line();if(!length)break;
            std::string_view row(line,length);size_t p=0;
            while(p<row.size()&&(row[p]==' '||row[p]=='\t'||row[p]=='\r'||row[p]=='\n'))++p;
            if(p==row.size()||row[p]==';')continue;
            require(p==0&&row[0]!='$',"flat syntax requires explicit owner and no directives");
            std::array<std::string_view,5> fields{};
            for(auto& field:fields){size_t first=p;
                while(p<row.size()&&row[p]!=' '&&row[p]!='\t'&&row[p]!='\r'&&row[p]!='\n')++p;
                field=row.substr(first,p-first);
                while(p<row.size()&&(row[p]==' '||row[p]=='\t'||row[p]=='\r'||row[p]=='\n'))++p;
            }
            require(!fields[0].empty()&&fields[0].back()=='.'&&equal_ascii(fields[2],"IN"),"flat syntax requires absolute IN owner");
            uint32_t ttl=0;
            require(!fields[1].empty(),"missing explicit flat TTL");
            auto parsed=std::from_chars(fields[1].data(),fields[1].data()+fields[1].size(),ttl);
            require(parsed.ec==std::errc{}&&parsed.ptr==fields[1].data()+fields[1].size(),"flat TTL must be decimal uint32");
            bool simple=equal_ascii(fields[3],"NS")&&!fields[4].empty()&&fields[4].back()=='.'&&
                plain_name(fields[0]) && plain_name(fields[4]) &&
                (p==row.size()||row[p]==';');
            if(simple){
                if(fields[0]!=previous_text){previous_text.assign(fields[0]);owner_wire=name_wire(previous_text);}
                uint64_t hash=checksum(reinterpret_cast<const uint8_t*>(fields[4].data()),fields[4].size());
                Slot& slot=cache[hash&(cache.size()-1)];
                if(slot.text_length==fields[4].size() && std::memcmp(slot.text.data(),fields[4].data(),fields[4].size())==0){++hits;}
                else{
                    ++misses;std::string target=name_wire(std::string(fields[4]));
                    require(target.size()<=slot.wire.size(),"normalized NS target exceeds fixed cache slot");
                    cached_bytes=cached_bytes-slot.text_length-slot.wire_length+fields[4].size()+target.size();
                    slot.text_length=fields[4].size();slot.wire_length=target.size();
                    std::memcpy(slot.text.data(),fields[4].data(),fields[4].size());
                    std::memcpy(slot.wire.data(),target.data(),target.size());
                }
                std::string wire;wire.reserve(owner_wire.size()+10+slot.wire_length);wire+=owner_wire;
                wire.push_back(0);wire.push_back(2);wire.push_back(0);wire.push_back(1);
                for(int shift=24;shift>=0;shift-=8)wire.push_back((ttl>>shift)&255);
                wire.push_back(slot.wire_length>>8);wire.push_back(slot.wire_length&255);
                wire.append(slot.wire.data(),slot.wire_length);
                consume(wire);
            }else{
                ldns_rr* rr=nullptr;
                ldns_status status=ldns_rr_new_frm_str(&rr,line,ttl,origin,&previous);
                require(status==LDNS_STATUS_OK&&rr,"flat fallback RR parse failed at record "+std::to_string(rows+1));
                std::string wire=canonical_wire(rr);ldns_rr_free(rr);consume(wire);++fallbacks;
            }
            ++rows;
            if(rows%16000000==0)std::cerr<<"STAGE {\"stage\":\"flat_normalization_progress\",\"records\":"<<rows<<"}\n";
        }
        require(!std::ferror(input),"flat source read failed");
    }catch(...){std::fclose(input);ldns_rdf_deep_free(origin);ldns_rdf_deep_free(previous);throw;}
    std::fclose(input);ldns_rdf_deep_free(origin);ldns_rdf_deep_free(previous);
    std::cerr<<"STAGE {\"stage\":\"flat_normalization_counts\",\"records\":"<<rows
        <<",\"cache_hits\":"<<hits<<",\"cache_misses\":"<<misses<<",\"ldns_fallbacks\":"<<fallbacks
        <<",\"cache_string_bytes\":"<<cached_bytes<<",\"fixed_cache_slot_bytes\":"<<cache.size()*sizeof(Slot)<<"}\n";
}
