// Optional bounded-window parser frontend. Library primitives are simdzone's;
// canonical RR events still enter the same verified owner-order construction.
#ifdef ZIMDB_USE_SIMDZONE
size_t lowercase_simd_name(std::string&wire,size_t start){
    size_t p=start;
    while(true){
        require(p<wire.size(),"truncated SIMD DNS name");
        unsigned length=static_cast<unsigned char>(wire[p++]);
        require(length<=63&&length<=wire.size()-p,"invalid SIMD DNS label");
        if(!length)break;
        for(size_t i=0;i<length;++i){unsigned char c=wire[p+i];if(c>='A'&&c<='Z')wire[p+i]=c+('a'-'A');}
        p+=length;
    }
    require(p-start<=255,"SIMD DNS name exceeds protocol bound");
    return p;
}

struct SimdZoneContext{
    const std::function<void(const std::string&)>*consume;
    std::string wire;
    std::exception_ptr error;
    uint64_t records=0,fallbacks=0;
};

int32_t accept_simd_rr(zone_parser_t*,const zone_name_t*owner,uint16_t type,uint16_t klass,
                       uint32_t ttl,uint16_t rdlength,const uint8_t*rdata,void*opaque){
    auto&context=*static_cast<SimdZoneContext*>(opaque);
    try{
        auto&wire=context.wire;
        wire.assign(reinterpret_cast<const char*>(owner->octets),owner->length);
        require(lowercase_simd_name(wire,0)==wire.size(),"invalid SIMD owner length");
        wire.push_back(type>>8);wire.push_back(type&255);
        wire.push_back(klass>>8);wire.push_back(klass&255);
        for(int shift=24;shift>=0;shift-=8)wire.push_back((ttl>>shift)&255);
        wire.push_back(rdlength>>8);wire.push_back(rdlength&255);
        size_t body=wire.size();
        wire.append(reinterpret_cast<const char*>(rdata),rdlength);
        // Only these known layouts bypass ldns canonicalization. All other
        // types retain the existing general canonical wire implementation.
        switch(type){
          case 2:require(lowercase_simd_name(wire,body)==wire.size(),"invalid SIMD NS length");break;
          case 6:{size_t p=lowercase_simd_name(wire,body);p=lowercase_simd_name(wire,p);
                  require(p+20==wire.size(),"invalid SIMD SOA length");break;}
          case 46:require(rdlength>=19,"short SIMD RRSIG");lowercase_simd_name(wire,body+18);break;
          case 1:case 16:case 28:case 43:case 48:case 50:case 51:break;
          default:wire=recanonicalize_wire(wire);++context.fallbacks;break;
        }
        (*context.consume)(wire);++context.records;
        if(context.records%16000000==0)std::cerr<<"STAGE {\"stage\":\"simd_normalization_progress\",\"records\":"<<context.records<<"}\n";
        return ZONE_SUCCESS;
    }catch(...){context.error=std::current_exception();return ZONE_BAD_PARAMETER;}
}

void read_simd_zone(const std::string&path,const std::string&origin_text,
                    const std::function<void(const std::string&)>&consume){
    std::string origin=name_wire(origin_text);
    zone_options_t options{};
    options.secondary=true;options.no_includes=true;options.pretty_ttls=true;
    options.origin={static_cast<uint8_t>(origin.size()),reinterpret_cast<const uint8_t*>(origin.data())};
    options.default_ttl=3600;options.default_class=ZONE_CLASS_IN;
    options.accept.callback=accept_simd_rr;
    auto parser=std::make_unique<zone_parser_t>();
    auto owner=std::make_unique<zone_name_buffer_t>();
    auto rdata=std::make_unique<zone_rdata_buffer_t>();
    zone_buffers_t buffers{1,owner.get(),rdata.get()};
    SimdZoneContext context{&consume,{},nullptr,0,0};
    context.wire.reserve(kMaxWire);
    int32_t status=zone_parse(parser.get(),&options,&buffers,path.c_str(),&context);
    if(context.error)std::rethrow_exception(context.error);
    require(status==ZONE_SUCCESS,"simdzone parse failed with status "+std::to_string(status));
    std::cerr<<"STAGE {\"stage\":\"simd_normalization_counts\",\"records\":"<<context.records
      <<",\"ldns_wire_fallbacks\":"<<context.fallbacks<<",\"source_window_bytes\":"<<ZONE_WINDOW_SIZE
      <<",\"parser_state_bytes\":"<<sizeof(zone_parser_t)<<",\"owner_buffer_bytes\":"<<sizeof(zone_name_buffer_t)
      <<",\"rdata_buffer_bytes\":"<<sizeof(zone_rdata_buffer_t)<<"}\n";
}
#endif
