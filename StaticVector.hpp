#pragma once

#include "WireDefs.h"
#include <stdexcept>

template<typename T, byte4 Capacity>
class StaticVector 
{
public:
    StaticVector();
    StaticVector(const StaticVector<T, Capacity>& other);
    StaticVector(const void* begin, const void* end);
    StaticVector(const char* str);

    constexpr byte4 capacity() const;
    byte4 size() const;
    byte4 count() const;
    bool empty() const;
    void push_back(const T& val);
    void pop_back();

    void insert(const byte* ptr, const byte4 size);
    void erase_back(const byte4 count);

    template<typename... Args>
    void emplace_back(Args&&... args);

    T& front();
    T& back();
    const T& front() const;
    const T& back() const;


    void resize(byte4 newSize, const T& val = T());

    T& operator[](byte4 index);
    const T& operator[](byte4 index) const;

    T* begin();
    T* end();
    const T* begin() const;
    const T* end() const;

    const char* c_str() const;

private:
    byte m_data[Capacity];
    byte4 m_size = 0;
};

template<typename T, byte4 Capacity>
inline StaticVector<T, Capacity>::StaticVector()
    : m_data{}, m_size(0)
{
}

template<typename T, byte4 Capacity>
inline StaticVector<T, Capacity>::StaticVector(const StaticVector<T, Capacity>& other)
{
    m_size = other.m_size;
    for (byte4 i = 0; i < m_size; i++)
    {
        m_data[i] = other.m_data[i];
    }
}

template<typename T, byte4 Capacity>
inline StaticVector<T, Capacity>::StaticVector(const void* begin, const void* end)
{
    const byte* beginPtr = reinterpret_cast<const byte*>(begin);
    const byte* endPtr = reinterpret_cast<const byte*>(end);

    resize(endPtr - beginPtr);

    std::memcpy(m_data, beginPtr, m_size);
}

template<typename T, byte4 Capacity>
inline StaticVector<T, Capacity>::StaticVector(const char* str)
{
    byte4 index = 0;

    while (str[index] != '\0' && index < Capacity)
    {
        m_data[index] = str[index];
        index++;
    }

    if (index < Capacity)
    {
        m_data[index++] = '\0';
    }

    m_size = index;
}

template<typename T, byte4 Capacity>
inline constexpr byte4 StaticVector<T, Capacity>::capacity() const
{
    return Capacity;
}

template<typename T, byte4 Capacity>
inline byte4 StaticVector<T, Capacity>::size() const
{
    return m_size;
}

template<typename T, byte4 Capacity>
inline byte4 StaticVector<T, Capacity>::count() const
{
    return m_size / sizeof(T);
}

template<typename T, byte4 Capacity>
inline bool StaticVector<T, Capacity>::empty() const
{
    return m_size == 0;
}

template<typename T, byte4 Capacity>
inline void StaticVector<T, Capacity>::push_back(const T& val)
{
    if (m_size + sizeof(T) >= Capacity)
        throw std::overflow_error("StaticVector overflow");

    T* ptr = reinterpret_cast<T*>(&m_data[m_size]);
    *ptr = val;

    m_size += sizeof(T);
}

template<typename T, byte4 Capacity>
inline void StaticVector<T, Capacity>::pop_back()
{
    if (empty())
        throw std::runtime_error("StaticVector is empty");

    m_size -= sizeof(T);
}

template<typename T, byte4 Capacity>
inline void StaticVector<T, Capacity>::insert(const byte* ptr, const byte4 size)
{
    byte* end = m_data + m_size;
    if (m_size + size > Capacity)
    {
        throw std::runtime_error("Invalid size");
    }

    std::memcpy(end, ptr, size);

    m_size += size;
}

template<typename T, byte4 Capacity>
inline void StaticVector<T, Capacity>::erase_back(const byte4 count)
{
    byte4 totalBytes = count * sizeof(T);
    if (totalBytes > m_size)
    {
        throw std::runtime_error("erase back overflow");
    }

    m_size -= totalBytes;
}

template<typename T, byte4 Capacity>
inline void StaticVector<T, Capacity>::resize(byte4 newCount, const T& val)
{
    byte4 newSize = newCount * sizeof(T); 

    if (newSize > Capacity)
    {
        throw std::overflow_error("Resize overflow");
    }
    
    m_size = newSize;
}

template<typename T, byte4 Capacity>
inline T& StaticVector<T, Capacity>::operator[](byte4 index)
{
    return *reinterpret_cast<T*>(&m_data[index * sizeof(T)]);
}

template<typename T, byte4 Capacity>
inline const T& StaticVector<T, Capacity>::operator[](byte4 index) const
{
    return *reinterpret_cast<const T*>(&m_data[index * sizeof(T)]);
}

template<typename T, byte4 Capacity>
inline T* StaticVector<T, Capacity>::begin()
{
    return reinterpret_cast<T*>(&m_data[0]);
}

template<typename T, byte4 Capacity>
inline T* StaticVector<T, Capacity>::end()
{
    return reinterpret_cast<T*>(&m_data[m_size]);
}

template<typename T, byte4 Capacity>
inline const T* StaticVector<T, Capacity>::begin() const
{
    return reinterpret_cast<const T*>(&m_data[0]);
}

template<typename T, byte4 Capacity>
inline const T* StaticVector<T, Capacity>::end() const
{
    return reinterpret_cast<const T*>(&m_data[m_size]);
}

template<typename T, byte4 Capacity>
inline const char* StaticVector<T, Capacity>::c_str() const
{
    return reinterpret_cast<const char*>(&m_data[0]);
}

template<typename T, byte4 Capacity>
template<typename... Args>
inline void StaticVector<T, Capacity>::emplace_back(Args && ...args)
{
    if (m_size + sizeof(T) > Capacity)
    {
        throw std::runtime_error("Ran out of memory");
    }

    T* ptr = reinterpret_cast<T*>(&m_data[m_size]);
    new (ptr) T(std::forward<Args>(args)...);
    m_size += sizeof(T);
}

template<typename T, byte4 Capacity>
inline T& StaticVector<T, Capacity>::front()
{
    if (empty())
        throw std::runtime_error("StaticVector is empty");
    return *reinterpret_cast<T*>(&m_data[0]);
}

template<typename T, byte4 Capacity>
inline const T& StaticVector<T, Capacity>::front() const
{
    if (empty())
        throw std::runtime_error("StaticVector is empty");
    return *reinterpret_cast<const T*>(&m_data[0]);
}

template<typename T, byte4 Capacity>
inline T& StaticVector<T, Capacity>::back()
{
    if (empty())
        throw std::runtime_error("StaticVector is empty");
    return *reinterpret_cast<T*>(&m_data[m_size - sizeof(T)]);
}

template<typename T, byte4 Capacity>
inline const T& StaticVector<T, Capacity>::back() const
{
    if (empty())
        throw std::runtime_error("StaticVector is empty");
    return *reinterpret_cast<const T*>(&m_data[m_size - sizeof(T)]);
}

template<typename T, byte4 Capacity>
inline bool operator==(const StaticVector<T, Capacity>& vec, const char* str)
{
    const byte* vecData = reinterpret_cast<const byte*>(vec.begin());

    if (vec.empty())
        return str[0] == '\0';

    return std::strcmp(reinterpret_cast<const char*>(vecData), str) == 0;
}
template<typename T, byte4 CapA, byte4 CapB>
inline bool operator==(const StaticVector<T, CapA>& a, const StaticVector<T, CapB>& b)
{
    if (a.size() != b.size())
        return false;

    return std::memcmp(a.begin(), b.begin(), a.size()) == 0;
}
