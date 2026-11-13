#ifndef ZIMDB_GROUPED_PRIMARY
#define ZIMDB_GROUPED_PRIMARY 1
#endif
#if ZIMDB_GROUPED_PRIMARY
constexpr char kOwnerPrimaryMagic[8]={'Z','I','M','O','W','N','1','\0'};
#else
constexpr char kOwnerPrimaryMagic[8]={'Z','I','M','F','L','T','1','\0'};
#endif

size_t primary_varint(uint8_t*out,uint64_t value){
    size_t n=0;do{uint8_t byte=value&127;value>>=7;out[n++]=byte|(value?128:0);}while(value);return n;
}

class OwnerPrimaryWriter {
public:
    explicit OwnerPrimaryWriter(FILE*file):file_(file){append(kOwnerPrimaryMagic,8);}
    void begin_owner(const std::string&key,uint64_t records){
        require(key.size()<=kMaxKey&&records,"invalid primary owner group");
#if ZIMDB_GROUPED_PRIMARY
        uint8_t header[12];header[0]=key.size()&255;header[1]=key.size()>>8;
        size_t n=primary_varint(header+2,records);append(header,2+n);append(key.data(),key.size());
#else
        owner_=key;
#endif
    }
    void body(std::string_view wire){
        require(wire.size()<=kMaxWire+1,"primary body exceeds protocol bound");
#if ZIMDB_GROUPED_PRIMARY
        uint8_t header[10];size_t n=primary_varint(header,wire.size());append(header,n);
#else
        uint8_t header[6]={static_cast<uint8_t>(owner_.size()),static_cast<uint8_t>(owner_.size()>>8),
            static_cast<uint8_t>(wire.size()),static_cast<uint8_t>(wire.size()>>8),static_cast<uint8_t>(wire.size()>>16),static_cast<uint8_t>(wire.size()>>24)};
        append(header,6);append(owner_.data(),owner_.size());
#endif
        append(wire.data(),wire.size());
    }
    void flush(){if(used_){write_all(file_,buffer_.data(),used_);used_=0;}}
    uint64_t bytes()const{return bytes_;}
private:
    void append(const void*data,size_t bytes){
        const auto*next=static_cast<const uint8_t*>(data);bytes_+=bytes;
        while(bytes){size_t n=std::min(bytes,buffer_.size()-used_);std::memcpy(buffer_.data()+used_,next,n);
            used_+=n;next+=n;bytes-=n;if(used_==buffer_.size())flush();}
    }
    FILE*file_;std::array<uint8_t,65536>buffer_{};size_t used_=0;uint64_t bytes_=0;
    [[maybe_unused]] std::string_view owner_;
};

class OwnerPrimaryReader {
public:
    explicit OwnerPrimaryReader(FILE*file):file_(file){
        char magic[8];take(magic,8,false);require(std::memcmp(magic,kOwnerPrimaryMagic,8)==0,"invalid primary run format");
    }
    bool next(){
#if ZIMDB_GROUPED_PRIMARY
        if(!remaining_){
            uint8_t header[2];if(!take(header,2,true))return false;
            size_t key_size=header[0]|(static_cast<size_t>(header[1])<<8);remaining_=varint();
            require(key_size<=kMaxKey&&remaining_,"invalid primary group header");
            current_.key.resize(key_size);take(current_.key.data(),key_size,false);
        }
        uint64_t wire_size=varint();require(wire_size<=kMaxWire+1,"invalid primary body size");
        current_.wire.resize(wire_size);take(current_.wire.data(),wire_size,false);--remaining_;
#else
        uint8_t header[6];if(!take(header,6,true))return false;size_t p=0;
        uint64_t key_size=get16(header,6,p),wire_size=get32(header,6,p);
        require(key_size<=kMaxKey&&wire_size<=kMaxWire+1,"invalid flat primary frame");
        current_.key.resize(key_size);current_.wire.resize(wire_size);
        take(current_.key.data(),key_size,false);take(current_.wire.data(),wire_size,false);
#endif
        return true;
    }
    const SortFrame&frame()const{return current_;}
private:
    bool refill(){
        size_=std::fread(buffer_.data(),1,buffer_.size(),file_);position_=0;
        if(!size_)require(!std::ferror(file_),"primary run read error");
        return size_!=0;
    }
    bool take(void*destination,size_t bytes,bool allow_eof){
        auto*out=static_cast<uint8_t*>(destination);size_t copied=0;
        while(copied<bytes){
            if(position_==size_&&!refill()){
                if(allow_eof&&!copied)return false;
                throw std::runtime_error("truncated primary run");
            }
            size_t n=std::min(bytes-copied,size_-position_);std::memcpy(out+copied,buffer_.data()+position_,n);
            position_+=n;copied+=n;
        }
        return true;
    }
    uint8_t byte(){require(position_!=size_||refill(),"truncated primary varint");return buffer_[position_++];}
    uint64_t varint(){
        uint8_t first=byte();if(first<128)return first;uint64_t value=first&127;
        for(unsigned i=1;i<10;++i){uint8_t part=byte();require(i!=9||(part&254)==0,"primary varint overflow");
            value|=static_cast<uint64_t>(part&127)<<(7*i);if(!(part&128))return value;}
        throw std::runtime_error("overlong primary varint");
    }
    FILE*file_;std::array<uint8_t,65536>buffer_{};size_t position_=0,size_=0;
    [[maybe_unused]] uint64_t remaining_=0;SortFrame current_;
};
