#pragma once

#include "mem.h"

template <class T>
class Ptr
{
public:
    
    Ptr()
        : addr(0)
    {
    }
    
    explicit Ptr(Address address)
        : addr(address)
    {
    }
    
    template <class U>
    Ptr(const Ptr<U> &other)
        : addr(other.address())
    {
        T *const t = static_cast<U *>(nullptr);
    }
    
    Address address() const
    {
        return addr;
    }
    
    template <class U>
    Ptr<U> cast() const
    {
        return Ptr<U>(addr);
    }
    
    T *get(const MemState *mem) const
    {
        return mem_ptr<T>(addr, mem);
    }
    
    explicit operator bool() const
    {
        return addr != 0;
    }
    
private:
    
    Address addr;
};

static_assert(sizeof(Ptr<const void>) == 4, "Size of Ptr isn't 4 bytes.");
