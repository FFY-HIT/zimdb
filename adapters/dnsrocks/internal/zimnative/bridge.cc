// Engineering-only serving: same image, target-type selection and presence API.
#define ZIMDB_NS_POOL_CACHE_BLOCKS 256
#define main zimdb_encoding_cli_main
#include "../../../../experiments/queryable_zone/native_zone.cpp"
#undef main
#include "fast_reader.inc"
namespace {
struct ServingImage {ServingReader image;std::string text_origin;explicit ServingImage(const char*p):image(p),text_origin(name_text(image.origin())){}};
void append_be(Bytes&b,uint64_t n,unsigned width){for(unsigned i=width;i;--i)b.push_back(static_cast<uint8_t>(n>>(8*(i-1))));}
bool wire_key(ServingReader&image,const unsigned char*wire,size_t length,bool wildcard,std::string&key){
    require(length&&length<=255&&wire_name_length(wire,length)==length,"invalid authority wire owner");
    std::string name(reinterpret_cast<const char*>(wire),length);
    bool within=false;
    for(size_t p=0;p<name.size();){unsigned n=static_cast<uint8_t>(name[p]);
        for(unsigned j=0;j<n;++j){char&c=name[p+1+j];if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');}
        p+=n+1;if(!n)break;
    }
    for(size_t p=0;p<name.size();){if(name.size()-p==image.origin().size()&&name.compare(p,image.origin().size(),image.origin())==0){within=true;break;}unsigned n=static_cast<uint8_t>(name[p]);if(!n)break;p+=n+1;}
    if(!within)return false;
    if(wildcard)name.insert(0,std::string("\x01*",2));
    key=make_key(name,image.origin(),image.header().flags);return true;
}
unsigned char*result_bytes(const std::vector<Record>&rows,size_t*size){Bytes bytes;
    for(const auto&r:rows){require(r.klass==1,"authority adapter requires IN");append_be(bytes,r.type,2);append_be(bytes,r.ttl,4);append_be(bytes,r.multiplicity,8);append_be(bytes,r.rdata.size(),4);bytes.insert(bytes.end(),r.rdata.begin(),r.rdata.end());}
    auto*p=static_cast<unsigned char*>(std::malloc(std::max<size_t>(1,bytes.size())));require(p,"allocate owner response");if(!bytes.empty())std::memcpy(p,bytes.data(),bytes.size());*size=bytes.size();return p;
}
}
extern "C" {
void*zim_open(const char*p){try{return new ServingImage(p);}catch(const std::exception&e){std::fprintf(stderr,"ZimDB open: %s\n",e.what());return nullptr;}}
void zim_close(void*h){delete static_cast<ServingImage*>(h);}
const char*zim_origin(void*h){return static_cast<ServingImage*>(h)->text_origin.c_str();}
unsigned char*zim_lookup(void*h,const char*owner,size_t*size,int*found){
    *size=0;*found=0;try{auto&source=static_cast<ServingImage*>(h)->image;auto key=make_key(name_wire(owner),source.origin(),source.header().flags);auto result=source.lookup(key);*found=result.second!="absent";return result_bytes(result.first,size);
    }catch(const std::exception&e){std::fprintf(stderr,"ZimDB lookup: %s\n",e.what());return nullptr;}
}
int zim_inspect_wire(void*h,const unsigned char*wire,size_t length,int wild){
    try{auto&source=static_cast<ServingImage*>(h)->image;std::string key;if(!wire_key(source,wire,length,wild,key))return 0;return source.inspect(key);}
    catch(const std::exception&e){std::fprintf(stderr,"ZimDB inspect: %s\n",e.what());return-1;}
}
unsigned char*zim_lookup_wire(void*h,const unsigned char*wire,size_t length,int wild,const uint16_t*types,size_t count,size_t*size,int*found){
    *size=0;*found=0;try{auto&source=static_cast<ServingImage*>(h)->image;std::string key;if(!wire_key(source,wire,length,wild,key))return result_bytes({},size);
        auto result=source.lookup(key,types,count);*found=result.second!="absent";return result_bytes(result.first,size);
    }catch(const std::exception&e){std::fprintf(stderr,"ZimDB typed lookup: %s\n",e.what());return nullptr;}
}
}
