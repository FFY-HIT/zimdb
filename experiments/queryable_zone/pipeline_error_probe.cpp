#define main zimdb_core_main
#include "native_zone.cpp"
#undef main
int main(){
    uint32_t flags=kRrsetPageFlag|kFrontFlag|kCompactKeyFlag|kColumnPageFlag|kNsTemplateFlag|kNsec3PageLinkFlag;
    Record bad;bad.key=make_key(name_wire("bad.example."),name_wire("example."),flags);
    bad.type=46;bad.klass=1;bad.ttl=300;bad.multiplicity=1;bad.rdata="x";
    ColumnPageWorkers workers(2);auto failure=workers.submit({bad},flags,nullptr);
    bool propagated=false;
    try{failure.get();}catch(const std::runtime_error&e){propagated=std::string(e.what())=="short column RRSIG";}
    require(propagated,"worker exception did not propagate");
    Record good=bad;good.type=1;good.rdata=std::string("\xc0\x00\x02\x01",4);
    auto success=workers.submit({good},flags,nullptr).get();
    require(!success.bytes.empty()&&success.descriptor.record_count==1,"worker did not recover after failed task");
    std::cout<<"{\"status\":\"PASS_EXCEPTION_PROPAGATION_AND_NEXT_TASK\"}\n";
}
