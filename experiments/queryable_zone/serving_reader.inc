// Engineering reader for the EXISTING image format. No encoding/build changes.
// Cache directory entries and decoded pages with an 8 MiB LRU budget (one
// oversized in-flight page is allowed). Expand
// only the requested owner. Never construct an all-owner map or DNS name tree.
#include <list>
namespace {
class ServingReader {
    struct Directory {
        uint64_t offset, checksum;
        uint32_t stored, raw, records, key_offset;
        uint16_t key_length, codec;
    };
    struct Span {const uint8_t* data;size_t size;};
    struct Component {uint32_t raw,stored,codec,offset;uint64_t checksum;};
    struct Definition {uint32_t meta,residual,opaque,members;uint16_t kinds;};
    struct NameRef {uint32_t offset;uint16_t length;};
    struct Page {
        size_t number=0;Bytes container;std::array<Component,5> descriptions{};
        std::array<Bytes,5> decoded;std::array<bool,5> ready{};
        uint32_t count=0,groups=0,defs=0,version=0;
        size_t names_pos=0,refs_pos=0;std::string previous;Span owner_names{},owner_refs{};
        std::vector<NameRef> names;std::string name_arena;
        std::string_view name(size_t i)const{const auto&r=names[i];return{name_arena.data()+r.offset,r.length};}
        size_t lower_bound(std::string_view key)const{size_t lo=0,hi=names.size();while(lo<hi){size_t mid=lo+(hi-lo)/2;auto a=name(mid);size_t n=std::min(a.size(),key.size());int c=n?std::memcmp(a.data(),key.data(),n):0;if(c<0||(!c&&a.size()<key.size()))lo=mid+1;else hi=mid;}return lo;}
        std::vector<std::pair<uint32_t,uint32_t>> references;
        std::vector<Definition> definitions;
        bool metadata_ready=false;
        size_t bytes()const {
            size_t n=sizeof(Page)+container.capacity()+names.capacity()*sizeof(NameRef)+name_arena.capacity()+previous.capacity()+
                references.capacity()*sizeof(references[0])+definitions.capacity()*sizeof(Definition);
            for(const auto&s:decoded)n+=s.capacity();
            return n;
        }
    };
    struct Cached {std::unique_ptr<Page> page;size_t accounted=0;};
    using Queue=std::list<Cached>;
public:
    explicit ServingReader(const char*path,size_t budget=8*1024*1024):budget_(budget){
        Image source(path);header_=source.header();origin_=source.origin();path_=source.data_path();
        if(!(header_.flags&kColumnPageFlag)){fallback_=std::make_unique<Image>(path);return;}
        fd_=::open(path_.c_str(),O_RDONLY);syscheck(fd_>=0,"open serving image");
        struct stat st{};syscheck(::fstat(fd_,&st)==0,"stat serving image");size_=st.st_size;
        require(size_>=source.committed_bytes(),"short serving snapshot");
        directory_.reserve(header_.page_count);
        auto append=[&](const PageIndex& d){
            require(d.first_key_length<=kMaxKey&&d.decoded_size<=kMaxPage&&d.encoded_size<=kMaxPage&&d.codec<=2&&
                d.offset>=sizeof(ImageHeader)&&d.offset<=header_.index_offset&&d.encoded_size<=header_.index_offset-d.offset,"invalid serving directory");
            require(keys_.size()<=UINT32_MAX-d.first_key_length,"serving fence arena exceeds bound");
            Directory e{d.offset,d.checksum,d.encoded_size,d.decoded_size,d.record_count,
                static_cast<uint32_t>(keys_.size()),d.first_key_length,d.codec};
            keys_.append(reinterpret_cast<const char*>(d.first_key),d.first_key_length);directory_.push_back(e);
        };
        if(header_.flags&kCowIndexFlag){
            // Buffer index nodes rather than faulting the legacy full-file map.
            // Eight fixed 16 KiB windows bound transient directory-loading RSS.
            struct NodeWindow {uint64_t offset=UINT64_MAX;Bytes bytes;};
            std::array<NodeWindow,8>windows;Bytes crossing;
            auto node_at=[&](const CowRef&ref){
                validate_cow_ref(ref);uint64_t committed=source.committed_bytes();
                require(ref.offset<=committed&&ref.length<=committed-ref.offset,"serving node outside committed snapshot");
                constexpr uint64_t block=16384;uint64_t base=ref.offset/block*block;
                if(ref.length<=block-(ref.offset-base)){
                    auto&w=windows[(base/block)%windows.size()];
                    if(w.offset!=base){read_exact(base,w.bytes,std::min<uint64_t>(block,committed-base));w.offset=base;}
                    require(ref.offset-base+ref.length<=w.bytes.size(),"short serving node window");
                    return decode_cow_node(w.bytes.data()+ref.offset-base,ref.length,ref);
                }
                read_exact(ref.offset,crossing,ref.length);return decode_cow_node(crossing.data(),ref.length,ref);
            };
            std::function<void(const CowRef&)>visit=[&](const CowRef&ref){
                if(!ref.pages)return;CowNode node=node_at(ref);
                if(node.leaf)append(node.page);else{visit(node.left);visit(node.right);}
            };visit(source.cow_root());
        }else for(size_t i=0;i<header_.page_count;++i)append(source.index(i));
        require(directory_.size()==header_.page_count,"incomplete serving directory");
        for(size_t i=1;i<directory_.size();++i)require(!less(fence(i),fence(i-1)),"unsorted serving directory");
        // This mapping is used only by the small shared NS pool. Data pages use
        // buffered reads, like the native RocksDB reader; no whole-file prefault.
        void*p=::mmap(nullptr,size_,PROT_READ,MAP_PRIVATE,fd_,0);syscheck(p!=MAP_FAILED,"map serving pool");
        mapped_=static_cast<const uint8_t*>(p);
        if(header_.flags&kNsPoolFlag)pool_=std::make_unique<NsPoolReader>(mapped_,source.committed_bytes(),header_);
        verified_.assign((directory_.size()*6+7)/8,0);
    }
    ~ServingReader(){pool_.reset();if(mapped_)::munmap(const_cast<uint8_t*>(mapped_),size_);if(fd_>=0)::close(fd_);}
    ServingReader(const ServingReader&)=delete;
    const std::string&origin()const{return origin_;}
    const ImageHeader&header()const{return header_;}
    size_t directory_bytes()const{return directory_.capacity()*sizeof(Directory)+keys_.capacity()+verified_.capacity();}
    size_t cache_bytes()const{return used_;}

    // Same states and exact-owner semantics as Image::name_state/get_rrset.
    std::pair<std::vector<Record>,std::string> lookup(const std::string&key,const uint16_t*types=nullptr,size_t ntypes=0,bool metadata_only=false){
        if(fallback_){auto state=fallback_->name_state(key);auto rows=metadata_only?std::vector<Record>{}:fallback_->get_rrset(key,0);filter(rows,types,ntypes);return{std::move(rows),state};}
        std::vector<Record> rows;std::string state="absent";
        if(directory_.empty())return{std::move(rows),key.empty()?"ent":state};
        size_t first=first_page(key);
        for(size_t i=first;i<directory_.size();++i){
            if(i>first&&less(key,fence(i))){
                if(state=="absent"&&prefix(fence(i),key))state="ent";
                break;
            }
            Page&p=page(i);size_t found=seek_owner(p,key);
            if(found<p.names.size()){
                size_t owner=found;
                if(p.name(found)==key){state="explicit";if(!metadata_only)owner_records(p,owner,types,ntypes,rows);}
                else {if(state=="absent"&&prefix(p.name(found),key))state="ent";account(p);trim();break;}
            }
            account(p);trim();
        }
        if(key.empty()&&state=="absent")state="ent";
        return{std::move(rows),state};
    }
    unsigned inspect(const std::string&key){
        if(fallback_){auto state=fallback_->name_state(key);unsigned flags=state=="explicit"?1:state=="ent"?2:0;
            if(flags&1){if(fallback_->has_type(key,2))flags|=4;if(fallback_->has_type(key,6))flags|=8;}return flags;}
        if(directory_.empty())return key.empty()?2:0;
        unsigned result=0;size_t first=first_page(key);
        for(size_t i=first;i<directory_.size();++i){
            if(i>first&&less(key,fence(i))){if(!result&&prefix(fence(i),key))result=2;break;}
            Page&p=page(i);size_t it=seek_owner(p,key);
            if(it<p.names.size()){
                if(p.name(it)==key){
                    result|=1;auto refs=p.references[it];if(refs.first)result|=4;
                    if(refs.second){metadata(p);auto kinds=p.definitions[refs.second-1].kinds;if(kinds&1)result|=4;if(kinds&2)result|=8;}
                }else{if(!result&&prefix(p.name(it),key))result=2;account(p);trim();break;}
            }
            account(p);trim();
        }
        return !result&&key.empty()?2:result;
    }
private:
    static bool less(std::string_view a,std::string_view b){size_t n=std::min(a.size(),b.size());int c=n?std::memcmp(a.data(),b.data(),n):0;return c<0||(!c&&a.size()<b.size());}
    static bool prefix(std::string_view name,std::string_view key){return name.size()>key.size()&&std::memcmp(name.data(),key.data(),key.size())==0;}
    static bool wanted(unsigned type,const uint16_t*types,size_t n){if(!n)return true;for(size_t i=0;i<n;++i)if(types[i]==255||types[i]==type)return true;return false;}
    static void filter(std::vector<Record>&rows,const uint16_t*types,size_t n){rows.erase(std::remove_if(rows.begin(),rows.end(),[&](const Record&r){return !wanted(r.type,types,n);}),rows.end());}
    std::string_view fence(size_t i)const{const auto&d=directory_[i];return{keys_.data()+d.key_offset,d.key_length};}
    size_t first_page(std::string_view key)const{
        size_t lo=0,hi=directory_.size();while(lo<hi){size_t mid=lo+(hi-lo)/2;if(less(fence(mid),key))lo=mid+1;else hi=mid;}return lo?lo-1:0;
    }
    bool verified(size_t page,unsigned component)const{size_t bit=page*6+component;return verified_[bit/8]&(1U<<(bit%8));}
    void mark(size_t page,unsigned component){size_t bit=page*6+component;verified_[bit/8]|=1U<<(bit%8);}
    void read_exact(uint64_t offset,Bytes&bytes,size_t length){bytes.resize(length);size_t p=0;while(p<length){ssize_t n=::pread(fd_,bytes.data()+p,length-p,offset+p);if(n<0&&errno==EINTR)continue;syscheck(n>0,"read serving page");p+=n;}}
    Span stream(Page&p,unsigned i,bool check=true){
        const auto&d=p.descriptions[i];const uint8_t*input=p.container.data()+d.offset;
        if(!p.ready[i]){
            const uint8_t*raw=input;
            if(d.codec==0)require(d.raw==d.stored,"serving raw component length");
            else {p.decoded[i].resize(d.raw);size_t n=ZSTD_decompress(p.decoded[i].data(),d.raw,input,d.stored);require(!ZSTD_isError(n)&&n==d.raw,"serving Zstd component");raw=p.decoded[i].data();}
            p.ready[i]=true;
        }
        const uint8_t*raw=d.codec?p.decoded[i].data():input;
        if(check&&!verified(p.number,i+1)){require(checksum(raw,d.raw)==d.checksum,"serving component checksum");mark(p.number,i+1);}
        return{raw,d.raw};
    }
    // Independent FNV-1a chains are interleaved, preserving each checksum
    // bit for bit while hiding integer-multiply latency. Nothing is skipped.
    static std::array<uint64_t,3> checksums3(Span a,Span b,Span c){
        constexpr uint64_t initial=14695981039346656037ULL,prime=1099511628211ULL;
        uint64_t x=initial,y=initial,z=initial;size_t i=0,n=std::min({a.size,b.size,c.size});
        for(;i<n;++i){x=(x^a.data[i])*prime;y=(y^b.data[i])*prime;z=(z^c.data[i])*prime;}
        size_t j=i,k=i;
        while(j<a.size&&k<b.size){x=(x^a.data[j++])*prime;y=(y^b.data[k++])*prime;}
        while(j<a.size&&i<c.size){x=(x^a.data[j++])*prime;z=(z^c.data[i++])*prime;}
        while(k<b.size&&i<c.size){y=(y^b.data[k++])*prime;z=(z^c.data[i++])*prime;}
        for(;j<a.size;++j)x=(x^a.data[j])*prime;
        for(;k<b.size;++k)y=(y^b.data[k])*prime;
        for(;i<c.size;++i)z=(z^c.data[i])*prime;
        return{x,y,z};
    }
    void prime_owner_streams(Page&p){
        Span names=stream(p,0,false),refs=stream(p,1,false);p.owner_names=names;p.owner_refs=refs;
        if(!verified(p.number,0)||!verified(p.number,1)||!verified(p.number,2)){
            auto hashes=checksums3({p.container.data(),p.container.size()},names,refs);
            require(hashes[0]==directory_[p.number].checksum,"serving page checksum");
            require(hashes[1]==p.descriptions[0].checksum&&hashes[2]==p.descriptions[1].checksum,"serving owner streams checksum");
            mark(p.number,0);mark(p.number,1);mark(p.number,2);
        }
    }
    Page&page(size_t number){
        auto hit=cache_.find(number);if(hit!=cache_.end()){queue_.splice(queue_.begin(),queue_,hit->second);return*queue_.front().page;}
        auto fresh=std::make_unique<Page>();Page&p=*fresh;p.number=number;const auto&d=directory_[number];
        Bytes stored;read_exact(d.offset,stored,d.stored);
        if(!d.codec){require(d.raw==d.stored,"serving raw page length");p.container=std::move(stored);}
        else {p.container.resize(d.raw);if(d.codec==1){int n=LZ4_decompress_safe(reinterpret_cast<const char*>(stored.data()),reinterpret_cast<char*>(p.container.data()),stored.size(),p.container.size());require(n==static_cast<int>(d.raw),"serving LZ4 page");}
            else{size_t n=ZSTD_decompress(p.container.data(),d.raw,stored.data(),stored.size());require(!ZSTD_isError(n)&&n==d.raw,"serving Zstd outer page");}}
        size_t pos=0;auto raw=p.container.data();size_t size=p.container.size();uint32_t magic=get32(raw,size,pos);
        require(magic==0x314c435aU||magic==0x324c435aU||magic==0x334c435aU,"unsupported serving column format");p.version=(magic>>24)&255;
        p.count=get32(raw,size,pos);p.groups=get32(raw,size,pos);p.defs=get32(raw,size,pos);
        require(p.count==d.records&&p.count&&p.groups&&p.groups<=p.count&&p.defs<=p.groups&&p.count<=kMaxPage/8,"serving column counts");
        uint64_t total=0;for(auto&c:p.descriptions){c.raw=get32(raw,size,pos);c.stored=get32(raw,size,pos);c.codec=get32(raw,size,pos);c.checksum=get64(raw,size,pos);total+=c.raw;require(total<=kMaxPage&&(c.codec==0||c.codec==2),"serving component bounds");}
        for(auto&c:p.descriptions){require(c.stored<=size-pos,"truncated serving component");c.offset=pos;pos+=c.stored;}require(pos==size,"serving container tail");
        prime_owner_streams(p);p.previous.reserve(kMaxKey);p.names.reserve(p.groups);p.name_arena.reserve(p.groups*8ULL);p.references.reserve(p.groups);
        // Decode just the first owner to bind the page to its checked directory.
        decode_owner(p);
        queue_.push_front({std::move(fresh),0});cache_.emplace(number,queue_.begin());account(*queue_.front().page);return*queue_.front().page;
    }
    void decode_owner(Page&p){
        require(p.names.size()<p.groups,"serving owner cursor bound");
        Span names=p.owner_names,refs=p.owner_refs;size_t&np=p.names_pos;size_t&rp=p.refs_pos;
        uint64_t common=get_varint(names.data,names.size,np),suffix=get_varint(names.data,names.size,np);
        require(((header_.flags&kFrontFlag)||!common)&&common<=p.previous.size()&&common+suffix<=kMaxKey&&suffix<=names.size-np,"serving owner prefix");
        p.previous.resize(common);p.previous.append(reinterpret_cast<const char*>(names.data+np),suffix);np+=suffix;
        require(p.names.empty()||less(p.name(p.names.size()-1),p.previous),"serving owner order");
        require(p.previous.size()<=UINT16_MAX&&p.name_arena.size()<=UINT32_MAX-p.previous.size(),"serving owner arena bound");
        p.names.push_back({static_cast<uint32_t>(p.name_arena.size()),static_cast<uint16_t>(p.previous.size())});p.name_arena.append(p.previous);
        uint64_t shared=get_varint(refs.data,refs.size,rp),literal=get_varint(refs.data,refs.size,rp);
        require((shared||literal)&&shared<=UINT32_MAX&&literal<=p.defs&&(!shared||(pool_&&shared<=pool_->meta().entries)),"serving owner references");p.references.emplace_back(shared,literal);
        require(p.names.size()!=1||p.name(0)==fence(p.number),"serving first owner fence");
        if(p.names.size()==p.groups)require(np==names.size&&rp==refs.size,"serving owner stream accounting");
    }
    size_t seek_owner(Page&p,std::string_view key){
        while(p.names.size()<p.groups&&less(p.name(p.names.size()-1),key))decode_owner(p);
        return p.lower_bound(key);
    }
    void ensure_owner(Page&p,size_t count){require(count<=p.groups,"serving linked owner rank");while(p.names.size()<count)decode_owner(p);}
    // Advance one definition member without constructing its RDATA or consulting
    // unrelated pool entries. Residual/signature offsets remain exact.
    struct Member {uint16_t type,klass;uint32_t ttl;uint64_t mult,length,reference=0,hash_start=0;size_t inline_at=0,prefix=0,residual_at=0,opaque_at=0;};
    Member member(Page&p,Span meta,size_t&mp,size_t&rp,size_t&op){
        Member r;r.type=get16(meta.data,meta.size,mp);r.klass=get16(meta.data,meta.size,mp);r.ttl=get32(meta.data,meta.size,mp);r.mult=get_varint(meta.data,meta.size,mp);r.length=get_varint(meta.data,meta.size,mp);
        require(r.mult&&r.length<=65535,"serving RR header");r.residual_at=rp;r.opaque_at=op;
        if(r.type==2&&p.version>='2'){r.reference=get_varint(meta.data,meta.size,mp);if(!r.reference)rp+=r.length;else require(pool_&&r.reference<=pool_->meta().entries,"serving NS target ref");}
        else if(r.type==46){r.prefix=get_varint(meta.data,meta.size,mp);require(r.prefix<=r.length&&r.prefix<=meta.size-mp,"serving signature prefix");r.inline_at=mp;mp+=r.prefix;op+=r.length-r.prefix;}
        else if(r.type==43){require(r.length>=4&&meta.size-mp>=4,"serving DS header");r.inline_at=mp;mp+=4;op+=r.length-4;}
        else if(r.type==50&&p.version>='3'){r.reference=get_varint(meta.data,meta.size,mp);if(r.reference){r.hash_start=get_varint(meta.data,meta.size,mp);require(r.reference<=p.groups&&r.length>=20&&r.hash_start<=r.length-20,"serving NSEC3 link");rp+=r.length-20;}else rp+=r.length;}
        else rp+=r.length;
        require(rp<=p.descriptions[3].raw&&op<=p.descriptions[4].raw,"serving RR component bounds");return r;
    }
    void metadata(Page&p){
        if(p.metadata_ready)return;Span meta=stream(p,2);size_t mp=0,rp=0,op=0;p.definitions.reserve(p.defs);
        for(uint32_t i=0;i<p.defs;++i){uint64_t members=get_varint(meta.data,meta.size,mp);require(members&&members<=p.count,"serving definition members");Definition d{static_cast<uint32_t>(mp),static_cast<uint32_t>(rp),static_cast<uint32_t>(op),static_cast<uint32_t>(members),0};
            for(uint64_t j=0;j<members;++j){auto r=member(p,meta,mp,rp,op);if(r.type==2)d.kinds|=1;if(r.type==6)d.kinds|=2;}
            p.definitions.push_back(d);
        }
        require(mp==meta.size&&rp==p.descriptions[3].raw&&op==p.descriptions[4].raw,"serving definition accounting");p.metadata_ready=true;
    }
    std::string materialize(Page&p,const Member&r,Span meta){
        std::string value;
        if(r.type==2&&p.version>='2'&&r.reference){std::string entry=pool_->lookup(r.reference-1);require(entry.size()==r.length+1&&entry[0]=='T',"serving target pool entry");value=entry.substr(1);}
        else if(r.type==46){Span opaque=stream(p,4);value.assign(reinterpret_cast<const char*>(meta.data+r.inline_at),r.prefix);value.append(reinterpret_cast<const char*>(opaque.data+r.opaque_at),r.length-r.prefix);}
        else if(r.type==43){Span opaque=stream(p,4);value.assign(reinterpret_cast<const char*>(meta.data+r.inline_at),4);value.append(reinterpret_cast<const char*>(opaque.data+r.opaque_at),r.length-4);}
        else {Span residual=stream(p,3);
            if(r.type==50&&p.version>='3'&&r.reference){ensure_owner(p,r.reference);std::string name=owner_from_key(std::string(p.name(r.reference-1)),std::string(1,'\0'),header_.flags);require(name.size()==34&&static_cast<uint8_t>(name[0])==32&&name.back()==0,"serving linked owner");
                value.assign(reinterpret_cast<const char*>(residual.data+r.residual_at),r.hash_start);value+=binary_hash(name.substr(1,32));value.append(reinterpret_cast<const char*>(residual.data+r.residual_at+r.hash_start),r.length-20-r.hash_start);
                size_t checked=0;require(nsec3_next_position(value,checked)&&checked==r.hash_start,"serving linked NSEC3 prefix");
            }else value.assign(reinterpret_cast<const char*>(residual.data+r.residual_at),r.length);
        }
        return value;
    }
    void owner_records(Page&p,size_t owner,const uint16_t*types,size_t ntypes,std::vector<Record>&out){
        auto refs=p.references[owner];std::string key(p.name(owner));
        if(refs.first&&wanted(2,types,ntypes)){
            std::string entry=pool_->lookup(refs.first-1);auto rows=p.version>='2'?ns_definition_v2(entry):ns_definition(entry);
            for(auto&r:rows){r.key=key;if(p.version>='2')r.rdata=ns_target_expand(key,r.rdata,header_.flags);out.push_back(std::move(r));}
        }
        if(refs.second){metadata(p);const auto&d=p.definitions[refs.second-1];size_t mp=d.meta,rp=d.residual,op=d.opaque;Span meta=stream(p,2);
            for(uint32_t j=0;j<d.members;++j){auto r=member(p,meta,mp,rp,op);if(!wanted(r.type,types,ntypes))continue;
                Record row;row.key=key;row.type=r.type;row.klass=r.klass;row.ttl=r.ttl;row.multiplicity=r.mult;row.rdata=materialize(p,r,meta);
                if(row.type==2&&p.version>='2')row.rdata=ns_target_expand(key,row.rdata,header_.flags);out.push_back(std::move(row));}
        }
        std::sort(out.begin(),out.end(),[](const Record&a,const Record&b){if(a.type!=b.type)return a.type<b.type;if(a.klass!=b.klass)return a.klass<b.klass;if(a.ttl!=b.ttl)return a.ttl<b.ttl;if(a.rdata.size()!=b.rdata.size())return a.rdata.size()<b.rdata.size();return byte_less(a.rdata,b.rdata);});
    }
    void account(Page&p){auto it=cache_.at(p.number);size_t now=p.bytes();used_+=now-it->accounted;it->accounted=now;}
    void trim(){while(used_>budget_&&queue_.size()>1){auto it=std::prev(queue_.end());used_-=it->accounted;cache_.erase(it->page->number);queue_.erase(it);}}
    int fd_=-1;size_t size_=0,budget_,used_=0;const uint8_t*mapped_=nullptr;
    ImageHeader header_{};std::string origin_,keys_;fs::path path_;std::unique_ptr<Image>fallback_;std::unique_ptr<NsPoolReader>pool_;
    std::vector<Directory>directory_;std::vector<uint8_t>verified_;Queue queue_;std::unordered_map<size_t,Queue::iterator>cache_;
};
}
