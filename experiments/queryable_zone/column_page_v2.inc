// Owner-conditioned exact NS templates. All parameters and dictionaries are
// stored in the image; neither origin-specific code nor external state is used.
#ifndef ZIMDB_GROUP_NS_CONTEXT
#define ZIMDB_GROUP_NS_CONTEXT 1
#endif
std::string ns_target_template_relative(const std::string&relative,const std::string&target){
    std::string literal(1,'L');literal+=target;
    if(relative.empty())return literal;
    for(size_t p=0;p<target.size()&&static_cast<uint8_t>(target[p]);){
        size_t length=static_cast<uint8_t>(target[p]);
        require(length<=63&&length+1<=target.size()-p,"invalid NS target label");
        if(relative.size()<=target.size()-p&&target.compare(p,relative.size(),relative)==0){
            Bytes out;out.push_back('R');put_varint(out,p);
            out.insert(out.end(),target.begin(),target.begin()+p);
            out.insert(out.end(),target.begin()+p+relative.size(),target.end());
            if(out.size()<literal.size())return std::string(reinterpret_cast<const char*>(out.data()),out.size());
        }
        p+=length+1;
    }
    return literal;
}

[[maybe_unused]] std::string ns_target_template(const std::string&key,const std::string&target,uint32_t flags){
    std::string relative=owner_from_key(key,std::string(1,'\0'),flags);relative.pop_back();
    return ns_target_template_relative(relative,target);
}
void verify_ns_template_relative(const std::string&relative,const std::string&encoded,const std::string&target){
    require(!encoded.empty(),"empty NS template");
    if(encoded[0]=='L'){
        require(encoded.size()==target.size()+1&&std::memcmp(encoded.data()+1,target.data(),target.size())==0,"NS literal mismatch");
        require(!target.empty()&&target.size()<=255&&wire_name_length(reinterpret_cast<const uint8_t*>(target.data()),target.size())==target.size(),"invalid expanded NS target");
    }else{
        require(encoded[0]=='R'&&!relative.empty(),"invalid relative NS template");size_t p=1;
        auto prefix=get_varint(reinterpret_cast<const uint8_t*>(encoded.data()),encoded.size(),p);
        require(prefix<=encoded.size()-p,"truncated relative NS template");
        std::string expanded(encoded.data()+p,prefix);expanded+=relative;
        expanded.append(encoded.data()+p+prefix,encoded.size()-p-prefix);
        require(expanded==target,"NS relative mismatch");
        require(expanded.size()<=255&&wire_name_length(reinterpret_cast<const uint8_t*>(expanded.data()),expanded.size())==expanded.size(),"invalid expanded NS target");
    }
}
std::string ns_target_expand(const std::string&key,const std::string&encoded,uint32_t flags){
    require(!encoded.empty(),"empty NS template");std::string target;
    if(encoded[0]=='L')target=encoded.substr(1);
    else{
        require(encoded[0]=='R',"invalid NS template kind");size_t p=1;
        uint64_t prefix=get_varint(reinterpret_cast<const uint8_t*>(encoded.data()),encoded.size(),p);
        require(prefix<=encoded.size()-p,"truncated NS template prefix");
        std::string relative=owner_from_key(key,std::string(1,'\0'),flags);relative.pop_back();
        require(!relative.empty(),"empty relative NS parameter");
        target.assign(encoded.data()+p,prefix);target+=relative;
        target.append(encoded.data()+p+prefix,encoded.size()-p-prefix);
    }
    require(!target.empty()&&target.size()<=255&&wire_name_length(reinterpret_cast<const uint8_t*>(target.data()),target.size())==target.size(),"invalid expanded NS target");
    return target;
}

std::vector<Record> ns_definition_v2(const std::string&blob){
    require(!blob.empty()&&blob[0]=='S',"invalid NS template-set pool entry");
    return ns_definition(blob.substr(1));
}
Bytes encode_column_page_v2(const std::vector<Record>&records,bool front,uint32_t flags,NsPoolBuilder*pool){
    (void)flags;
    std::array<Bytes,5>streams;auto&names=streams[0];auto&refs=streams[1];auto&meta=streams[2];
    auto&residual=streams[3];auto&opaque=streams[4];
    std::map<std::string,uint32_t>local_ids;std::vector<std::vector<Record>>definitions;
    std::string previous;uint32_t groups=0;
    for(size_t first=0;first<records.size();){
        size_t last=first+1;while(last<records.size()&&records[last].key==records[first].key)++last;
        const auto&key=records[first].key;size_t common=0;
        if(front)while(common<key.size()&&common<previous.size()&&key[common]==previous[common])++common;
        put_varint(names,common);put_varint(names,key.size()-common);names.insert(names.end(),key.begin()+common,key.end());previous=key;
        std::vector<Record>ns,literal;
#if ZIMDB_GROUP_NS_CONTEXT
        std::string relative;bool relative_ready=false;
#endif
        for(size_t i=first;i<last;++i){
#if ZIMDB_GROUP_NS_CONTEXT
            const auto&source=records[i];Record r;
            r.type=source.type;r.klass=source.klass;r.ttl=source.ttl;r.multiplicity=source.multiplicity;
#else
            Record r=records[i];
#endif
            if(r.type==2){
#if ZIMDB_GROUP_NS_CONTEXT
                if(!relative_ready){relative=owner_from_key(key,std::string(1,'\0'),flags);relative.pop_back();relative_ready=true;}
                r.rdata=ns_target_template_relative(relative,source.rdata);
                verify_ns_template_relative(relative,r.rdata,records[i].rdata);
#else
                r.rdata=ns_target_template(key,r.rdata,flags);
                require(ns_target_expand(key,r.rdata,flags)==records[i].rdata,"NS template roundtrip mismatch");
#endif
                ns.push_back(std::move(r));
            }else{
#if ZIMDB_GROUP_NS_CONTEXT
                r.rdata=source.rdata;
#endif
                literal.push_back(std::move(r));
            }
        }
        uint32_t shared=0;bool pooled=!ns.empty()&&pool&&pool->intern_tagged(rr_definition(ns),shared,'S');
        put_varint(refs,pooled?static_cast<uint64_t>(shared)+1:0);
#if ZIMDB_GROUP_NS_CONTEXT
        if(!pooled)literal.insert(literal.end(),std::make_move_iterator(ns.begin()),std::make_move_iterator(ns.end()));
#else
        if(!pooled)literal.insert(literal.end(),ns.begin(),ns.end());
#endif
        std::sort(literal.begin(),literal.end(),[](const Record&a,const Record&b){
            if(a.type!=b.type)return a.type<b.type;
            if(a.klass!=b.klass)return a.klass<b.klass;
            if(a.ttl!=b.ttl)return a.ttl<b.ttl;
            return byte_less(a.rdata,b.rdata);
        });
        if(literal.empty())put_varint(refs,0);
        else{
            Bytes identity=rr_definition(literal);std::string key_bytes(reinterpret_cast<const char*>(identity.data()),identity.size());
            auto found=local_ids.find(key_bytes);uint32_t id;
            if(found==local_ids.end()){id=definitions.size();local_ids.emplace(std::move(key_bytes),id);definitions.push_back(std::move(literal));}
            else id=found->second;
            put_varint(refs,static_cast<uint64_t>(id)+1);
        }
        ++groups;first=last;
    }
    for(const auto&definition:definitions){
        put_varint(meta,definition.size());
        for(const auto&r:definition){
            put16(meta,r.type);put16(meta,r.klass);put32(meta,r.ttl);put_varint(meta,r.multiplicity);put_varint(meta,r.rdata.size());
            if(r.type==2){
                Bytes target(r.rdata.begin(),r.rdata.end());uint32_t id=0;
                bool shared=pool&&pool->intern_tagged(target,id,'T');
                put_varint(meta,shared?static_cast<uint64_t>(id)+1:0);
                if(!shared)residual.insert(residual.end(),target.begin(),target.end());
            }else if(r.type==46){
                require(r.rdata.size()>=19,"short column RRSIG");
                size_t prefix=18+wire_name_length(reinterpret_cast<const uint8_t*>(r.rdata.data()+18),r.rdata.size()-18);
                put_varint(meta,prefix);meta.insert(meta.end(),r.rdata.begin(),r.rdata.begin()+prefix);
                opaque.insert(opaque.end(),r.rdata.begin()+prefix,r.rdata.end());
            }else if(r.type==43){
                require(r.rdata.size()>=4,"short column DS");meta.insert(meta.end(),r.rdata.begin(),r.rdata.begin()+4);
                opaque.insert(opaque.end(),r.rdata.begin()+4,r.rdata.end());
            }else residual.insert(residual.end(),r.rdata.begin(),r.rdata.end());
        }
    }
    Bytes out;put32(out,0x324c435aU);put32(out,records.size());put32(out,groups);put32(out,definitions.size());
    std::array<Bytes,5>encoded;std::array<uint32_t,5>codecs{};uint64_t total=0;
    for(size_t i=0;i<streams.size();++i){
        total+=streams[i].size();
        if(i!=4&&!streams[i].empty()){
            encoded[i].resize(ZSTD_compressBound(streams[i].size()));
            size_t n=ZSTD_compress(encoded[i].data(),encoded[i].size(),streams[i].data(),streams[i].size(),3);
            require(!ZSTD_isError(n),"column compression failed");encoded[i].resize(n);
            if(n<streams[i].size())codecs[i]=2;
        }
        if(!codecs[i])encoded[i]=streams[i];
        put32(out,streams[i].size());put32(out,encoded[i].size());put32(out,codecs[i]);put64(out,checksum(streams[i].data(),streams[i].size()));
    }
    require(total<=kMaxPage,"column decoded streams exceed page bound");
    for(const auto&part:encoded)out.insert(out.end(),part.begin(),part.end());
    require(out.size()<=kMaxPage,"column container exceeds page bound");return out;
}

std::vector<Record> decode_column_page_v2(const Bytes&container,bool front,uint32_t flags,const NsPoolReader*pool){
    (void)flags;
    size_t p=0;require(get32(container.data(),container.size(),p)==0x324c435aU,"invalid column page magic");
    uint32_t count=get32(container.data(),container.size(),p),groups=get32(container.data(),container.size(),p),defs=get32(container.data(),container.size(),p);
    require(count&&count<=kMaxPage/8&&groups&&groups<=count&&defs<=groups,"invalid column counts");
    struct Description{uint32_t raw,stored,codec;uint64_t checksum;};std::array<Description,5>description{};
    uint64_t decoded_total=0;
    for(auto&d:description){d.raw=get32(container.data(),container.size(),p);d.stored=get32(container.data(),container.size(),p);
        d.codec=get32(container.data(),container.size(),p);d.checksum=get64(container.data(),container.size(),p);
        decoded_total+=d.raw;require(decoded_total<=kMaxPage&&(d.codec==0||d.codec==2),"invalid column component bound");}
    std::array<Bytes,5>streams;
    for(size_t i=0;i<streams.size();++i){const auto&d=description[i];require(d.stored<=container.size()-p,"truncated column component");
        streams[i].resize(d.raw);
        if(d.codec==0){require(d.raw==d.stored,"raw column length mismatch");if(d.raw)std::memcpy(streams[i].data(),container.data()+p,d.raw);}
        else{size_t n=ZSTD_decompress(streams[i].data(),streams[i].size(),container.data()+p,d.stored);require(!ZSTD_isError(n)&&n==d.raw,"column decompression failed");}
        require(checksum(streams[i].data(),streams[i].size())==d.checksum,"column checksum mismatch");p+=d.stored;
    }
    require(p==container.size(),"trailing column container bytes");
    size_t mp=0,rp=0,op=0;const auto&meta=streams[2];const auto&residual=streams[3];const auto&opaque=streams[4];
    std::vector<std::vector<Record>>definitions;definitions.reserve(defs);
    for(uint32_t i=0;i<defs;++i){uint64_t members=get_varint(meta.data(),meta.size(),mp);
        require(members&&members<=count,"invalid column definition count");std::vector<Record>values;values.reserve(members);
        for(uint64_t j=0;j<members;++j){Record r;r.type=get16(meta.data(),meta.size(),mp);r.klass=get16(meta.data(),meta.size(),mp);
            r.ttl=get32(meta.data(),meta.size(),mp);r.multiplicity=get_varint(meta.data(),meta.size(),mp);
            uint64_t length=get_varint(meta.data(),meta.size(),mp);require(r.multiplicity&&length<=65535,"invalid column RR metadata");
            if(r.type==2){
                uint64_t ref=get_varint(meta.data(),meta.size(),mp);
                if(ref){
                    require(pool&&ref-1<=UINT32_MAX,"invalid NS target pool reference");
                    std::string entry=pool->lookup(ref-1);
                    require(!entry.empty()&&entry[0]=='T'&&entry.size()-1==length,"invalid NS target pool entry");
                    r.rdata=entry.substr(1);
                }else{
                    require(length<=residual.size()-rp,"truncated NS target template");
                    if(length)r.rdata.assign(reinterpret_cast<const char*>(residual.data()+rp),length);
                    rp+=length;
                }
            }else if(r.type==46){uint64_t prefix=get_varint(meta.data(),meta.size(),mp);
                require(prefix<=length&&prefix<=meta.size()-mp&&length-prefix<=opaque.size()-op,"truncated column signature");
                r.rdata.assign(reinterpret_cast<const char*>(meta.data()+mp),prefix);mp+=prefix;
                if(length>prefix)r.rdata.append(reinterpret_cast<const char*>(opaque.data()+op),length-prefix);
                op+=length-prefix;
            }else if(r.type==43){require(length>=4&&meta.size()-mp>=4&&length-4<=opaque.size()-op,"truncated column DS");
                r.rdata.assign(reinterpret_cast<const char*>(meta.data()+mp),4);mp+=4;
                if(length>4)r.rdata.append(reinterpret_cast<const char*>(opaque.data()+op),length-4);
                op+=length-4;
            }else{require(length<=residual.size()-rp,"truncated column payload");
                if(length)r.rdata.assign(reinterpret_cast<const char*>(residual.data()+rp),length);
                rp+=length;}
            values.push_back(std::move(r));}
        definitions.push_back(std::move(values));
    }
    require(mp==meta.size()&&rp==residual.size()&&op==opaque.size(),"trailing column definition streams");
    std::vector<Record>records;records.reserve(count);std::string previous;
    size_t np=0,fp=0;const auto&names=streams[0];const auto&refs=streams[1];
    for(uint32_t i=0;i<groups;++i){uint64_t common=get_varint(names.data(),names.size(),np),suffix=get_varint(names.data(),names.size(),np);
        require((front||!common)&&common<=previous.size()&&common+suffix<=kMaxKey&&suffix<=names.size()-np,"invalid column owner front code");
        std::string key=previous.substr(0,common);if(suffix)key.append(reinterpret_cast<const char*>(names.data()+np),suffix);np+=suffix;
        require(!i||byte_less(previous,key),"unsorted column owners");
        uint64_t shared=get_varint(refs.data(),refs.size(),fp),literal=get_varint(refs.data(),refs.size(),fp);
        require(shared||literal,"empty column owner");std::vector<Record>values;
        if(shared){require(pool&&shared-1<=UINT32_MAX,"invalid column pool reference");values=ns_definition_v2(pool->lookup(shared-1));}
        if(literal){require(literal-1<definitions.size(),"column literal reference out of range");const auto&more=definitions[literal-1];values.insert(values.end(),more.begin(),more.end());}
        for(auto&r:values)if(r.type==2)r.rdata=ns_target_expand(key,r.rdata,flags);
        std::sort(values.begin(),values.end(),[](const Record&a,const Record&b){
            if(a.type!=b.type)return a.type<b.type;
            if(a.klass!=b.klass)return a.klass<b.klass;
            if(a.ttl!=b.ttl)return a.ttl<b.ttl;
            if(a.rdata.size()!=b.rdata.size())return a.rdata.size()<b.rdata.size();
            return byte_less(a.rdata,b.rdata);});
        require(values.size()<=count-records.size(),"column expansion exceeds RR count");
        for(auto&r:values){r.key=key;records.push_back(std::move(r));}previous=std::move(key);
    }
    require(np==names.size()&&fp==refs.size()&&records.size()==count,"column page count/stream mismatch");return records;
}
