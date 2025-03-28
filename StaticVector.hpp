#include <stdexcept>

template<typename T, size_t Capacity>
class StaticVector 
{
public:
    StaticVector();
    StaticVector(const StaticVector<T, Capacity>& other);
    StaticVector(const void* begin, const void* end);
    StaticVector(const char* str);

    constexpr size_t capacity() const;
    size_t size() const;
    bool empty() const;
    void push_back(const T& val);

    void resize(size_t newSize, const T& val = T());

    T& operator[](size_t index);
    const T& operator[](size_t index) const;

    T* begin();
    T* end();
    const T* begin() const;
    const T* end() const;

private:
    T m_data[Capacity * sizeof(T)];
    size_t m_size = 0;
};

template<typename T, size_t Capacity>
inline StaticVector<T, Capacity>::StaticVector()
    : m_data{}
{
}

template<typename T, size_t Capacity>
inline StaticVector<T, Capacity>::StaticVector(const StaticVector<T, Capacity>& other)
{
    m_size = other.m_size;
    for (size_t i = 0; i < m_size; i++)
    {
        m_data[i] = other.m_data[i];
    }
}

template<typename T, size_t Capacity>
inline StaticVector<T, Capacity>::StaticVector(const void* begin, const void* end)
{
    const byte* beginPtr = reinterpret_cast<const byte*>(begin);
    const byte* endPtr = reinterpret_cast<const byte*>(end);

    resize(endPtr - beginPtr);

    std::memcpy(m_data, beginPtr, m_size);
}

template<typename T, size_t Capacity>
inline StaticVector<T, Capacity>::StaticVector(const char* str)
{
    size_t index = 0;

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

template<typename T, size_t Capacity>
inline constexpr size_t StaticVector<T, Capacity>::capacity() const
{
    return Capacity;
}

template<typename T, size_t Capacity>
inline size_t StaticVector<T, Capacity>::size() const
{
    return m_size;
}

template<typename T, size_t Capacity>
inline bool StaticVector<T, Capacity>::empty() const
{
    return m_size == 0;
}

template<typename T, size_t Capacity>
inline void StaticVector<T, Capacity>::push_back(const T& val)
{
    if (m_size + sizeof(T) >= Capacity)
        throw std::overflow_error("StaticVector overflow");

    T* ptr = reinterpret_cast<T*>(&m_data[m_size]);
    *ptr = val;

    m_size += sizeof(T);
}

template<typename T, size_t Capacity>
inline void StaticVector<T, Capacity>::resize(size_t newCount, const T& val)
{
    size_t newSize = newCount * sizeof(T); 

    if (newSize > Capacity)
    {
        throw std::overflow_error("Resize overflow");
    }
    
    m_size = newSize;
}

template<typename T, size_t Capacity>
inline T& StaticVector<T, Capacity>::operator[](size_t index)
{
    return m_data[index];
}

template<typename T, size_t Capacity>
inline const T& StaticVector<T, Capacity>::operator[](size_t index) const
{
    return m_data[index];
}

template<typename T, size_t Capacity>
inline T* StaticVector<T, Capacity>::begin()
{
    return m_data;
}

template<typename T, size_t Capacity>
inline T* StaticVector<T, Capacity>::end()
{
    return m_data + m_size;
}

template<typename T, size_t Capacity>
inline const T* StaticVector<T, Capacity>::begin() const
{
    return m_data;
}

template<typename T, size_t Capacity>
inline const T* StaticVector<T, Capacity>::end() const
{
    return m_data + m_size;
}
