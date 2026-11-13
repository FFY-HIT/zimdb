#define main zimdb_core_main
#include "native_zone.cpp"
#undef main
#include <openssl/sha.h>

int main(int argc,char**argv){
    try{
        Options options=parse_options(argc,argv);
        auto start=Clock::now();Image image(options.need("image"));
        std::array<uint64_t,4> first{},second{};
        std::array<uint64_t,65536>types{};
        uint64_t count=0,wire_bytes=0;
        auto add=[](std::array<uint64_t,4>&sum,const std::array<uint8_t,32>&digest){
            uint64_t carry=0;
            for(size_t i=0;i<4;++i){uint64_t word=0;std::memcpy(&word,digest.data()+8*i,8);
                __uint128_t total=static_cast<__uint128_t>(sum[i])+word+carry;
                sum[i]=static_cast<uint64_t>(total);carry=total>>64;}
        };
        image.each([&](const Record&r){
            std::string wire=record_wire(r,image.origin(),nullptr,image.header().flags);
            std::array<uint8_t,32>a{},b{};SHA256_CTX ctx;
            SHA256_Init(&ctx);SHA256_Update(&ctx,wire.data(),wire.size());SHA256_Final(a.data(),&ctx);
            uint8_t prefix=1;SHA256_Init(&ctx);SHA256_Update(&ctx,&prefix,1);
            SHA256_Update(&ctx,wire.data(),wire.size());SHA256_Final(b.data(),&ctx);
            require(r.multiplicity<=UINT64_MAX-count,"fingerprint count overflow");
            for(uint64_t i=0;i<r.multiplicity;++i){add(first,a);add(second,b);}
            count+=r.multiplicity;wire_bytes+=wire.size()*r.multiplicity;types[r.type]+=r.multiplicity;
        });
        require(count==image.header().occurrences,"image occurrence count mismatch");
        std::cout<<"{\"records\":"<<count<<",\"wire_bytes\":"<<wire_bytes<<",\"type_counts\":{";
        bool emitted=false;for(uint32_t i=0;i<types.size();++i)if(types[i]){
            if(emitted)std::cout<<',';emitted=true;std::cout<<'\"'<<i<<"\":"<<types[i];}
        std::cout<<"},\"sha256_sum_mod_2_256_le\":"<<json_string(hex(reinterpret_cast<const uint8_t*>(first.data()),32))
                 <<",\"sha256_domain1_sum_mod_2_256_le\":"<<json_string(hex(reinterpret_cast<const uint8_t*>(second.data()),32))
                 <<",\"seconds\":"<<seconds_since(start)
                 <<",\"protocol\":\"complete canonical RR multiset, two SHA256 sums and exact counts; probabilistic verification\"}\n";
    }catch(const std::exception&e){std::cerr<<"ERROR "<<e.what()<<'\n';return 1;}
}
