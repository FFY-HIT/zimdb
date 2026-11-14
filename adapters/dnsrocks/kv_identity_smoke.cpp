#include <rocksdb/db.h>
#include <iostream>
#include <memory>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::DB* opened = nullptr;
    auto status = rocksdb::DB::Open(options, argv[1], &opened);
    if (!status.ok()) { std::cerr << status.ToString(); return 1; }
    std::unique_ptr<rocksdb::DB> database(opened);
    rocksdb::WriteOptions write;
    write.sync = true;
    std::string frames("\x01\0\0\0Z", 5);
    frames += std::string("\x02\0\0\0A0", 6);
    frames += std::string("\x01\0\0\0Z", 5);
    status = database->Put(write, std::string("\0/", 2), frames);
    if (!status.ok()) return 1;
    status = database->Put(write, std::string("\0o_features", 11), std::string("\x01\0\0\0Z", 5));
    if (!status.ok()) return 1;
    rocksdb::FlushOptions flush;
    flush.wait = true;
    status = database->Flush(flush);
    return status.ok() ? 0 : 1;
}
