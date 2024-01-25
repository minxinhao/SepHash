#pragma once
#include <stdint.h>

template <class T, class KeyType,class ValueType>
concept KVTrait = requires(T t,KeyType k,ValueType v) {
    t.insert(k,v);
    t.search(k,v);
    t.remove(k);
    t.update(k,v);
};

class BasicDB{
public:
  BasicDB(){

  }
  virtual ~BasicDB(){

  }
};