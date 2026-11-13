// Fixed-worker, bounded-inflight column-page construction. Only a sealed pool
// may be shared; the main thread alone writes extents and the ordered index.
struct PreparedColumnPage { Bytes bytes; PageIndex descriptor{}; };

PreparedColumnPage prepare_column_page(const std::vector<Record>&records,uint32_t flags,NsPoolBuilder*pool){
    require(!records.empty()&&(flags&kColumnPageFlag),"invalid parallel column page");
    PreparedColumnPage result;
    result.bytes=encode_page(records,flags&kPoolFlag,flags&kFrontFlag,flags,pool);
    auto&entry=result.descriptor;
    require(result.bytes.size()<=kMaxPage&&records.front().key.size()<=kMaxKey,"parallel page bound");
    entry.encoded_size=entry.decoded_size=result.bytes.size();entry.record_count=records.size();
    entry.first_key_length=records.front().key.size();entry.codec=0;
    entry.checksum=checksum(result.bytes.data(),result.bytes.size());
    std::memcpy(entry.first_key,records.front().key.data(),entry.first_key_length);
    return result;
}

class ColumnPageWorkers {
public:
    explicit ColumnPageWorkers(size_t count):queue_limit_(count+1){
        try{for(size_t i=0;i<count;++i)threads_.emplace_back([this]{run();});}
        catch(...){shutdown();throw;}
    }
    ~ColumnPageWorkers(){shutdown();}
    std::future<PreparedColumnPage> submit(std::vector<Record>records,uint32_t flags,NsPoolBuilder*pool){
        auto task=std::make_shared<std::packaged_task<PreparedColumnPage()>>(
            [records=std::move(records),flags,pool]{return prepare_column_page(records,flags,pool);});
        auto future=task->get_future();
        {std::lock_guard<std::mutex>lock(mutex_);
            require(!stop_&&jobs_.size()<queue_limit_,"page worker queue bound");
            jobs_.emplace_back([task]{(*task)();});}
        ready_.notify_one();return future;
    }
private:
    void shutdown(){
        {std::lock_guard<std::mutex>lock(mutex_);stop_=true;}
        ready_.notify_all();for(auto&thread:threads_)if(thread.joinable())thread.join();
    }
    void run(){
        while(true){
            std::function<void()>job;
            {std::unique_lock<std::mutex>lock(mutex_);
                ready_.wait(lock,[this]{return stop_||!jobs_.empty();});
                if(stop_&&jobs_.empty())return;
                job=std::move(jobs_.front());jobs_.pop_front();}
            job();
        }
    }
    size_t queue_limit_;bool stop_=false;
    std::mutex mutex_;std::condition_variable ready_;
    std::deque<std::function<void()>>jobs_;std::vector<std::thread>threads_;
};
