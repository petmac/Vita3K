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
        static_assert(std::is_convertible<U *, T *>::value, "Ptr is not convertible.");
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
        if (addr == 0)
        {
            return nullptr;
        }
        else
        {
            return reinterpret_cast<T *>(&mem->memory[addr]);
        }
    }
    
    explicit operator bool() const
    {
        return addr != 0;
    }
    
private:
    
    Address addr;
};

static_assert(sizeof(Ptr<const void>) == 4, "Size of Ptr isn't 4 bytes.");

template <class T>
Ptr<T> operator+(const Ptr<T> &base, int32_t offset)
{
    return Ptr<T>(base.address() + (offset * sizeof(T)));
}

template <class T>
Ptr<T> alloc(MemState *mem, const char *name)
{
    const Address address = alloc(mem, sizeof(T), name);
    const Ptr<T> ptr(address);
    if (!ptr)
    {
        return ptr;
    }
    
    T *const memory = ptr.get(mem);
    new (memory) T;
    
    return ptr;
}
