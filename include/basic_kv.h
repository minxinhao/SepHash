#pragma once
#include <map>

template<typename key_t,typename val_t>
class Noop_Kv
{
private:
    std::map<key_t,val_t> keys;
public:
    Noop_Kv(/* args */){

    }
    ~Noop_Kv(){

    }

    bool insert(key_t& key , val_t& val){
        if(keys.find(key)!=keys.end()){
            return false;
        }else{
            keys[key] = val;
            return true;
        }
    }

    bool search(key_t& key, val_t& val){
        auto iter = keys.find(key);
        if(iter==keys.end()){
            return false;
        }else{
            val = iter->second;
            return true;
        }
    }
};


