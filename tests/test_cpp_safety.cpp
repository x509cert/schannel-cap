#include <cassert>
#include <crtdbg.h>
#include <type_traits>
#include <utility>

#define main capture_program_main
#ifdef TEST_TLS_GROUP
#include "..\tls_group.cpp"
#else
#include "..\schannel_etw.cpp"
#endif
#undef main

static_assert(sizeof(HeapPtr<unsigned char[]>) == sizeof(unsigned char *));
static_assert(std::is_empty_v<FreeDeleter>);
static_assert(std::is_nothrow_constructible_v<HeapPtr<unsigned char[]>, unsigned char *>);
static_assert(std::is_nothrow_move_constructible_v<HeapPtr<unsigned char[]>>);
static_assert(!std::is_copy_constructible_v<HeapPtr<unsigned char[]>>);

#ifdef TEST_TLS_GROUP
static_assert(std::is_same_v<decltype(MAX_REASSEMBLY_FLOWS), const int>);
static_assert(std::is_same_v<decltype(MAX_TLS_RECORD_BYTES), const unsigned int>);
static_assert(MAX_REASSEMBLY_FLOWS == 256 && MAX_TLS_RECORD_BYTES == 65540u);
#else
static_assert(std::is_same_v<decltype(SESSION_NAME_CAPACITY), const int>);
static_assert(std::is_same_v<decltype(MAX_TDH_ALLOCATION), const unsigned long>);
static_assert(std::is_same_v<decltype(MAX_TCP_TABLE_ALLOCATION), const unsigned long>);
static_assert(std::is_same_v<decltype(SEEN_SLOTS), const int>);
static_assert(std::is_same_v<decltype(MAP_LINE_CAPACITY), const int>);
static_assert(std::is_same_v<decltype(MAX_KV), const int>);
static_assert(std::is_same_v<decltype(FAILURE_DETAIL_CAPACITY), const int>);
static_assert(SESSION_NAME_CAPACITY == 64 && MAX_TDH_ALLOCATION == 16UL * 1024UL * 1024UL);
static_assert(MAX_TCP_TABLE_ALLOCATION == 64UL * 1024UL * 1024UL && SEEN_SLOTS == 32768);
static_assert(MAP_LINE_CAPACITY == 224 && MAX_KV == 64 && FAILURE_DETAIL_CAPACITY == 4096);
#endif

static void exercise_buffer_lifetimes()
{
    HeapPtr<unsigned char[]> empty = nullptr;
    assert(!empty);
    HeapPtr<unsigned char[]> buffer(static_cast<unsigned char *>(calloc(32, 1)));
    assert(buffer && buffer[0] == 0 && buffer[31] == 0);
    buffer[31] = 42;
    auto moved = std::move(buffer);
    assert(!buffer && moved[31] == 42);
    moved.reset(static_cast<unsigned char *>(malloc(64)));
    assert(moved);
    moved[63] = 42;
}

#ifndef TEST_TLS_GROUP
static int reject_allocation(int type, void *, size_t, int blockType,
                             long, const unsigned char *, int)
{
    return type != _HOOK_ALLOC || blockType != _NORMAL_BLOCK;
}

static void exercise_etw_helpers()
{
    DWORD pid = 0;
    assert(parse_pid("42", &pid) && pid == 42);
    assert(!parse_pid("not-a-pid", &pid));

    struct {
        TRACE_EVENT_INFO info;
        WCHAR name[8];
    } metadata = {};
    metadata.info.PropertyCount = 1;
    metadata.info.TopLevelPropertyCount = 1;
    auto &property = metadata.info.EventPropertyInfoArray[0];
    property.NameOffset = (ULONG)offsetof(decltype(metadata), name);
    property.count = 1;
    property.length = sizeof(ULONG);
    property.nonStructType.InType = TDH_INTYPE_UINT32;
    property.nonStructType.OutType = TDH_OUTTYPE_UNSIGNEDINT;
    (void)wcscpy_s(metadata.name, L"Status");

    ULONG value = 42;
    EVENT_RECORD event = {};
    event.UserData = &value;
    event.UserDataLength = sizeof(value);
    USHORT length = 0;
    assert(prop_length(&event, &metadata.info, sizeof(metadata), 0, &length));
    assert(length == sizeof(value));
    KV decoded[1] = {};
    assert(decode_props(&event, &metadata.info, sizeof(metadata), decoded, 1) == 1);
    assert(strcmp(decoded[0].name, "Status") == 0 && strcmp(decoded[0].val, "42") == 0);

    // Exercise the retained realloc path when TDH needs more than 512 bytes.
    WCHAR large[401];
    for (size_t i = 0; i < ARRAYSIZE(large) - 1; ++i) large[i] = L'A';
    large[400] = L'\0';
    event.UserData = large;
    event.UserDataLength = sizeof(large);
    property.length = 0;
    property.nonStructType.InType = TDH_INTYPE_UNICODESTRING;
    property.nonStructType.OutType = TDH_OUTTYPE_STRING;
    assert(decode_props(&event, &metadata.info, sizeof(metadata), decoded, 1) == 1);
    assert(strcmp(decoded[0].val, "?") == 0); // Existing output-size fallback.

    assert(open_output_file(L"invalid<name>.tmp") == nullptr);
    assert(GetLastError() == ERROR_INVALID_NAME);
    _CRT_ALLOC_HOOK oldHook = _CrtSetAllocHook(reject_allocation);
    FILE *file = open_output_file(L"unused.tmp");
    DWORD error = GetLastError();
    _CrtSetAllocHook(oldHook);
    assert(file == nullptr && error == ERROR_OUTOFMEMORY);
}
#endif

int main()
{
    _CrtMemState before, after, difference;
    _CrtMemCheckpoint(&before);
    exercise_buffer_lifetimes();
#ifndef TEST_TLS_GROUP
    exercise_etw_helpers();
#endif
    _CrtMemCheckpoint(&after);
    assert(!_CrtMemDifference(&difference, &before, &after));

// Optional negative compilation checks: these must fail with /we4834.
#ifdef TEST_NODISCARD
#ifdef TEST_TLS_GROUP
    reassembly_acquire("source", "destination");
#else
    DWORD pid;
    USHORT length;
    parse_pid("42", &pid);
    prop_length(nullptr, nullptr, 0, 0, &length);
    info_string(nullptr, 0, 0);
    decode_props(nullptr, nullptr, 0, nullptr, 0);
    open_output_file(nullptr);
#endif
#endif
    puts("PASS: C++ safety helpers.");
    return 0;
}
