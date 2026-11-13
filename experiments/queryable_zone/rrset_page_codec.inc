// Page-local factorization: one front-coded owner and one RR-multiset ID.
// Dictionaries and literal fallbacks are stored inside each independently
// compressed page. No cross-page state is needed by lookup or generation update.
Bytes encode_rrset_page(const std::vector<Record>& records, bool front, uint32_t flags, NsPoolBuilder* ns_pool) {
    Bytes names, references, definitions;
    std::map<std::string, uint32_t> ids;
    std::string previous;
    uint32_t groups = 0;
    for (size_t first = 0; first < records.size();) {
        size_t last = first+1;
        while (last < records.size() && records[last].key == records[first].key) ++last;
        const auto& key = records[first].key;
        size_t common = 0;
        if (front) while (common < previous.size() && common < key.size() && previous[common] == key[common]) ++common;
        put_varint(names, common);
        put_varint(names, key.size()-common);
        names.insert(names.end(), key.begin()+common, key.end());
        previous = key;
        ++groups;
        Bytes blob;
        put_varint(blob, last-first);
        for (size_t i = first; i < last; ++i) {
            const auto& record = records[i];
            std::string transformed;
            const std::string* payload = &record.rdata;
            if ((flags & kNsec3NextKeyFlag) && record.type == 50) {
                transformed = encode_nsec3_next(record.rdata, flags);
                payload = &transformed;
            }
            put16(blob, record.type);
            put16(blob, record.klass);
            put32(blob, record.ttl);
            put_varint(blob, record.multiplicity);
            put_varint(blob, payload->size());
            blob.insert(blob.end(), payload->begin(), payload->end());
        }
        if (flags & kNsPoolFlag) {
            bool all_ns = std::all_of(records.begin()+first, records.begin()+last, [](const Record& r){ return r.type == 2; });
            uint32_t shared_id = 0;
            bool shared = all_ns && ns_pool && ns_pool->intern(blob, shared_id);
            Bytes tagged;
            put_varint(tagged, shared ? 1 : 0);
            if (shared) put_varint(tagged, shared_id);
            else tagged.insert(tagged.end(), blob.begin(), blob.end());
            blob.swap(tagged);
        }
        std::string identity(reinterpret_cast<const char*>(blob.data()), blob.size());
        auto found = ids.find(identity);
        uint32_t id;
        if (found == ids.end()) {
            id = ids.size();
            ids.emplace(std::move(identity), id);
            put_varint(definitions, blob.size());
            definitions.insert(definitions.end(), blob.begin(), blob.end());
        } else id = found->second;
        put_varint(references, id);
        first = last;
    }
    Bytes raw;
    put32(raw, 0x3153525aU); // ZRS1
    put32(raw, records.size());
    put32(raw, groups);
    put32(raw, ids.size());
    put32(raw, names.size());
    put32(raw, references.size());
    raw.insert(raw.end(), names.begin(), names.end());
    raw.insert(raw.end(), references.begin(), references.end());
    raw.insert(raw.end(), definitions.begin(), definitions.end());
    require(raw.size() <= kMaxPage, "RRset page exceeds decoded bound");
    return raw;
}

std::vector<Record> decode_rrset_page(const Bytes& raw, bool front, uint32_t flags, const NsPoolReader* ns_pool) {
    size_t position = 0;
    require(get32(raw.data(), raw.size(), position) == 0x3153525aU, "invalid RRset page magic");
    uint32_t count = get32(raw.data(), raw.size(), position);
    uint32_t groups = get32(raw.data(), raw.size(), position);
    uint32_t definitions = get32(raw.data(), raw.size(), position);
    uint32_t names_length = get32(raw.data(), raw.size(), position);
    uint32_t refs_length = get32(raw.data(), raw.size(), position);
    require(count && count <= ((flags & kNsPoolFlag) ? kMaxPage/8 : raw.size()) && groups && groups <= count &&
            definitions && definitions <= groups, "invalid RRset page counts");
    require(names_length <= raw.size()-position, "truncated RRset names");
    size_t names_start = position, names_end = position+names_length;
    position = names_end;
    require(refs_length <= raw.size()-position, "truncated RRset references");
    size_t refs_start = position, refs_end = position+refs_length;
    position = refs_end;
    std::vector<std::vector<Record>> dictionary;
    dictionary.reserve(definitions);
    for (uint32_t i = 0; i < definitions; ++i) {
        uint64_t bytes = get_varint(raw.data(), raw.size(), position);
        require(bytes <= raw.size()-position, "truncated RRset definition");
        Bytes definition(raw.begin()+position,raw.begin()+position+bytes);
        position += bytes;
        bool shared = false;
        if (flags & kNsPoolFlag) {
            size_t tag_position = 0;
            uint64_t mode = get_varint(definition.data(),definition.size(),tag_position);
            require(mode <= 1,"invalid NS pool reference mode");
            if (mode == 1) {
                uint64_t id = get_varint(definition.data(),definition.size(),tag_position);
                require(ns_pool && id <= UINT32_MAX && tag_position == definition.size(),"invalid NS pool reference");
                std::string shared_blob = ns_pool->lookup(id);
                definition.assign(shared_blob.begin(),shared_blob.end());
                shared = true;
            } else definition.erase(definition.begin(),definition.begin()+tag_position);
        }
        size_t p=0;
        uint64_t members=get_varint(definition.data(),definition.size(),p);
        require(members && members <= count && members <= definition.size(),"invalid RRset member count");
        std::vector<Record> values;values.reserve(members);
        for(uint64_t j=0;j<members;++j){
            Record record;
            record.type=get16(definition.data(),definition.size(),p);
            record.klass=get16(definition.data(),definition.size(),p);
            record.ttl=get32(definition.data(),definition.size(),p);
            record.multiplicity=get_varint(definition.data(),definition.size(),p);
            require(record.multiplicity && (!shared || record.type == 2),"invalid shared NS member");
            uint64_t length=get_varint(definition.data(),definition.size(),p);
            require(length<=definition.size()-p && length<=65535+46,"invalid RRset payload length");
            record.rdata.assign(reinterpret_cast<const char*>(definition.data()+p),length);p+=length;
            if((flags & kNsec3NextKeyFlag) && record.type==50)record.rdata=decode_nsec3_next(record.rdata,flags);
            require(record.rdata.size()<=65535,"RRset decoded payload too large");
            values.push_back(std::move(record));
        }
        require(p==definition.size(),"trailing RRset definition bytes");
        dictionary.push_back(std::move(values));
    }
    require(position == raw.size(), "trailing RRset page bytes");
    std::vector<Record> records;
    records.reserve(count);
    size_t name_pos = names_start, ref_pos = refs_start;
    std::string previous;
    for (uint32_t i = 0; i < groups; ++i) {
        uint64_t common = get_varint(raw.data(), names_end, name_pos);
        uint64_t suffix = get_varint(raw.data(), names_end, name_pos);
        require((front || !common) && common <= previous.size() &&
                common+suffix <= kMaxKey && suffix <= names_end-name_pos, "invalid RRset name front code");
        std::string key = previous.substr(0, common);
        key.append(reinterpret_cast<const char*>(raw.data()+name_pos), suffix);
        name_pos += suffix;
        require(!i || byte_less(previous, key), "RRset names not strictly sorted");
        uint64_t id = get_varint(raw.data(), refs_end, ref_pos);
        require(id < dictionary.size(), "RRset reference out of range");
        require(dictionary[id].size() <= count-records.size(), "RRset expansion exceeds page count");
        for (const auto& value : dictionary[id]) {
            records.push_back(value);
            records.back().key = key;
        }
        previous = std::move(key);
    }
    require(name_pos == names_end && ref_pos == refs_end && records.size() == count,
            "RRset page count/stream mismatch");
    return records;
}
