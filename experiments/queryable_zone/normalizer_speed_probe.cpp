#define main zimdb_core_main
#include "native_zone.cpp"
#undef main
#include <openssl/sha.h>

int main(int argc,char**argv){
  try{
    require(argc==4,"usage: normalizer_speed_probe flat|simd source origin");
    SHA256_CTX hash;SHA256_Init(&hash);uint64_t records=0,bytes=0;
    std::map<unsigned,uint64_t>types;
    auto consume=[&](const std::string&wire){
      size_t n=wire_name_length(reinterpret_cast<const uint8_t*>(wire.data()),wire.size());
      require(n+10<=wire.size(),"probe RR header");
      ++types[(static_cast<unsigned char>(wire[n])<<8)|static_cast<unsigned char>(wire[n+1])];
      SHA256_Update(&hash,wire.data(),wire.size());++records;bytes+=wire.size();
    };
    auto start=Clock::now();std::string mode=argv[1];
    if(mode=="flat")read_flat_zone(argv[2],argv[3],consume);
    else if(mode=="simd")read_simd_zone(argv[2],argv[3],consume);
    else require(false,"invalid probe parser");
    double elapsed=seconds_since(start);
    unsigned char digest[32];SHA256_Final(digest,&hash);
    std::ostringstream hex;hex<<std::hex<<std::setfill('0');for(auto b:digest)hex<<std::setw(2)<<unsigned(b);
    rusage usage{};getrusage(RUSAGE_SELF,&usage);
    std::cout<<"{\"status\":\"PARSER_COMPONENT_ONLY\",\"mode\":"<<json_string(mode)
      <<",\"seconds_not_T_build\":"<<elapsed<<",\"records\":"<<records<<",\"wire_bytes\":"<<bytes
      <<",\"ordered_wire_sha256\":"<<json_string(hex.str())<<",\"child_peak_RSS_KiB\":"<<usage.ru_maxrss<<",\"type_counts\":{";
    bool first=true;for(auto [type,count]:types){if(!first)std::cout<<',';first=false;std::cout<<json_string(std::to_string(type))<<':'<<count;}
    std::cout<<"}}\n";
  }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
}
