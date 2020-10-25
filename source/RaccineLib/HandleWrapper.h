#pragma once
#pragma once
#pragma once

#include <Windows.h>

template< class traits >
class HandleWrapper final
{
public:
    HandleWrapper() :
        m_handle(traits::InvalidValue)
    {
    }

    HandleWrapper(typename traits::HandleType value) :
        m_handle(value)
    {
    }

    ~HandleWrapper()
    {
        Close();
    }

    void Close()
    {
        if (m_handle != traits::InvalidValue) {
            traits::Close(m_handle);
            m_handle = traits::InvalidValue;
        }
    }

    bool operator !() const
    {
        return m_handle == traits::InvalidValue;
    }

    operator bool() const
    {
        return m_handle != traits::InvalidValue;
    }

    operator typename traits::HandleType()
    {
        return m_handle;
    }

    typename traits::HandleType* operator&()
    {
        return &m_handle;
    }

private:
    typename traits::HandleType m_handle;
};

// Handle wrapper for handles from CreateToolhelp32Snapshot
struct SnapshotHandleTraits
{
    typedef HANDLE HandleType;
    inline static const HANDLE InvalidValue = INVALID_HANDLE_VALUE;

    static void Close(HANDLE value)
    {
        CloseHandle(value);
    }
};

// Handle wrapper for handles from OpenProcess
struct ProcessHandleTraits
{
    typedef HANDLE HandleType;
    inline static const HANDLE InvalidValue = NULL;

    static void Close(HANDLE value)
    {
        CloseHandle(value);
    }
};

// Handle wrapper for handles from RegisterEventSourceW
struct EventSourceHandleTraits
{
    typedef HANDLE HandleType;
    inline static const HANDLE InvalidValue = NULL;

    static void Close(HANDLE value)
    {
        DeregisterEventSource(value);
    }
};

// Handle wrapper for handles from FindFirstFileW
struct FindFileHandleTraits
{
    typedef HANDLE HandleType;
    inline static const HANDLE InvalidValue = INVALID_HANDLE_VALUE;

    static void Close(HANDLE value)
    {
        FindClose(value);
    }
};

// Handle wrapper for handles from OpenProcessToken
struct TokenHandleTraits
{
    typedef HANDLE HandleType;
    inline static const HANDLE InvalidValue = INVALID_HANDLE_VALUE;

    static void Close(HANDLE value)
    {
        CloseHandle(value);
    }
};

// Handle wrapper for handles from OpenEvent
struct EventHandleTraits
{
    typedef HANDLE HandleType;
    inline static const HANDLE InvalidValue = NULL;

    static void Close(HANDLE value)
    {
        CloseHandle(value);
    }
};

using SnapshotHandleWrapper = HandleWrapper< SnapshotHandleTraits>;
using ProcessHandleWrapper = HandleWrapper< ProcessHandleTraits>;
using EventSourceHandleWrapper = HandleWrapper< EventSourceHandleTraits>;
using FindFileHandleWrapper = HandleWrapper< FindFileHandleTraits>;
using TokenHandleWrapper = HandleWrapper< TokenHandleTraits>;
using EventHandleWrapper = HandleWrapper< EventHandleTraits>;
