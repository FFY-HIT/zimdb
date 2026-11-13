Bytes encode_column_page_v3(const std::vector<Record>&records,bool front,uint32_t flags,NsPoolBuilder*pool){
    (void)flags;
    std::map<std::string,uint32_t>owner_ordinals;
    for(const auto&r:records)if(!owner_ordinals.count(r.key))owner_ordinals.emplace(r.key,owner_ordinals.size());
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
            }else if(r.type==50){
                size_t hash_start=0;uint64_t reference=0;
                if(nsec3_next_position(r.rdata,hash_start)){
                    std::string label=base32hex_hash(r.rdata.data()+hash_start);
                    std::string name(1,static_cast<char>(label.size()));name+=label;name.push_back('\0');
                    std::string next=make_key(name,std::string(1,'\0'),flags);
                    auto found=owner_ordinals.find(next);
                    if(found!=owner_ordinals.end())reference=static_cast<uint64_t>(found->second)+1;
                }
                put_varint(meta,reference);
                if(reference){
                    put_varint(meta,hash_start);
                    residual.insert(residual.end(),r.rdata.begin(),r.rdata.begin()+hash_start);
                    residual.insert(residual.end(),r.rdata.begin()+hash_start+20,r.rdata.end());
                }else residual.insert(residual.end(),r.rdata.begin(),r.rdata.end());
            }else residual.insert(residual.end(),r.rdata.begin(),r.rdata.end());
        }
    }
    Bytes out;put32(out,0x334c435aU);put32(out,records.size());put32(out,groups);put32(out,definitions.size());
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

std::vector<Record> decode_column_page_v3(const Bytes&container,bool front,uint32_t flags,const NsPoolReader*pool){
    (void)flags;
    size_t p=0;require(get32(container.data(),container.size(),p)==0x334c435aU,"invalid column page magic");
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
    size_t np=0;const auto&names=streams[0];std::string previous;
    std::vector<std::string>owner_keys;owner_keys.reserve(groups);
    for(uint32_t i=0;i<groups;++i){
        uint64_t common=get_varint(names.data(),names.size(),np),suffix=get_varint(names.data(),names.size(),np);
        require((front||!common)&&common<=previous.size()&&common+suffix<=kMaxKey&&suffix<=names.size()-np,"invalid linked-column owner front code");
        std::string key=previous.substr(0,common);if(suffix)key.append(reinterpret_cast<const char*>(names.data()+np),suffix);np+=suffix;
        require(!i||byte_less(previous,key),"unsorted linked-column owners");owner_keys.push_back(key);previous=std::move(key);
    }
    require(np==names.size(),"trailing linked-column names");
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
            }else if(r.type==50){
                uint64_t reference=get_varint(meta.data(),meta.size(),mp);
                if(reference){
                    uint64_t hash_start=get_varint(meta.data(),meta.size(),mp);
                    require(reference-1<owner_keys.size()&&length>=20&&hash_start<=length-20&&length-20<=residual.size()-rp,"invalid linked NSEC3 bounds");
                    std::string name=owner_from_key(owner_keys[reference-1],std::string(1,'\0'),flags);
                    require(name.size()==34&&static_cast<uint8_t>(name[0])==32&&name.back()==0,"invalid linked NSEC3 owner");
                    if(hash_start)r.rdata.assign(reinterpret_cast<const char*>(residual.data()+rp),hash_start);
                    r.rdata+=binary_hash(name.substr(1,32));
                    if(length-20>hash_start)r.rdata.append(reinterpret_cast<const char*>(residual.data()+rp+hash_start),length-20-hash_start);
                    rp+=length-20;size_t checked=0;
                    require(nsec3_next_position(r.rdata,checked)&&checked==hash_start,"linked NSEC3 prefix mismatch");
                }else{
                    require(length<=residual.size()-rp,"truncated literal NSEC3");
                    if(length)r.rdata.assign(reinterpret_cast<const char*>(residual.data()+rp),length);
                    rp+=length;
                }
            }else{require(length<=residual.size()-rp,"truncated column payload");
                if(length)r.rdata.assign(reinterpret_cast<const char*>(residual.data()+rp),length);
                rp+=length;}
            values.push_back(std::move(r));}
        definitions.push_back(std::move(values));
    }
    require(mp==meta.size()&&rp==residual.size()&&op==opaque.size(),"trailing column definition streams");
    std::vector<Record>records;records.reserve(count);
    size_t fp=0;const auto&refs=streams[1];
    for(uint32_t i=0;i<groups;++i){const std::string&key=owner_keys[i];
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
        for(auto&r:values){r.key=key;records.push_back(std::move(r));}
    }
    require(np==names.size()&&fp==refs.size()&&records.size()==count,"column page count/stream mismatch");return records;
}
