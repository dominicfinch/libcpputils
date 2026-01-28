#pragma once

#include "interfaces/storage.h"
#include <sstream>

namespace iar { namespace app { 

class LocalStorageSink : public iar::app::cloud_storage_sink
{
public:
    LocalStorageSink(std::string bucket, std::string prefix) :
        _bucket(std::move(bucket)), _prefix(std::move(prefix))
    {}

    bool open(const std::string& object_name) override {
        _object_name = _prefix + "/" + object_name;
        //_stream.emplace(_client.WriteObject(_bucket, _object_name));
        return true;
    }

    bool write(const uint8_t* data, size_t size) override {
        //_stream->write(reinterpret_cast<const char*>(data), size);
        //return _stream->good();
        return false;
    }

    bool close() override {
        //_stream->Close();
        return true;
    }

    std::string object_uri() const override {
        return "gs://" + _bucket + "/" + _object_name;
    }

private:
    std::string _bucket;
    std::string _prefix;
    std::string _object_name;
};

} }