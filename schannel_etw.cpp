/*
 * schannel_etw.cpp  --  TLS connection-map writer + ETW listener (no injection)
 *
 * Runs quietly and keeps a PID map current for the offline group decode:
 *   - Continuously snapshots the TCP table (GetExtendedTcpTable) and writes
 *     "localIP:port remoteIP:port PID" to conns.txt next to this exe.
 *     tls_group.exe joins ServerHello 4-tuples against it to attach the owning
 *     PID -- exact, loopback-safe, no ETW field-name guessing.
 *   - Opens the Schannel + TCPIP ETW session so -v can dump raw events for
 *     diagnostics. Without -v nothing is printed but a "Listening..." banner;
 *     the authoritative TLS output is tls_group's post-capture decode.
 *
 *  -v            : dump every property of every event (TDH self-describing)
 *  <pid> / -p N  : with -v, restrict the dump to one process
 *
 * conns.txt is (re)created next to the exe. Run ELEVATED. Ctrl+C stops.
 *
 * BUILD (any arch):
 *   cl /nologo /O2 /MT /W4 /GS /guard:cf /Qspectre /sdl /analyze ^
 *      /std:c++20 /permissive- /EHsc schannel_etw.cpp ^
 *      /link /DYNAMICBASE /NXCOMPAT ^
 *      /guard:cf tdh.lib advapi32.lib iphlpapi.lib ws2_32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <sal.h>
#include <strsafe.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define SESSION_NAME_CAPACITY 64
#define MAX_TDH_ALLOCATION (16UL * 1024UL * 1024UL)
#define MAX_TCP_TABLE_ALLOCATION (64UL * 1024UL * 1024UL)

static const GUID SchannelGuid =
    { 0x1F678132,0x5938,0x4686,{0x9F,0xDC,0xC8,0xFF,0x68,0xF1,0x5C,0x85} };
static const GUID TcpipGuid =
    { 0x2F07E2EE,0x15DB,0x40F1,{0x90,0xEF,0x9D,0x7B,0xA2,0x82,0x18,0x8A} };

static TRACEHANDLE             g_session = 0;
static TRACEHANDLE             g_trace   = (TRACEHANDLE)INVALID_HANDLE_VALUE;
static PEVENT_TRACE_PROPERTIES g_props   = NULL;
static WCHAR                   g_sessionName[SESSION_NAME_CAPACITY];
static int                     g_verbose = 0;
static DWORD                   g_filterPid = 0;
static volatile LONG           g_running = 1;
static volatile LONG           g_sessionStarted = 0;

/* ---- connection map (conns.txt) writer ---------------------------------- */
static FILE            *g_map = NULL;
static CRITICAL_SECTION g_mapLock;
#define SEEN_SLOTS 32768
#define MAP_LINE_CAPACITY 224
static unsigned long long g_seenHashes[SEEN_SLOTS];
static char g_seenLines[SEEN_SLOTS][MAP_LINE_CAPACITY];

static int seen_add(_In_z_ const char *s)
{
    unsigned long long h = 1469598103934665603ULL;
    size_t i; unsigned idx, probe;
    if (!s) return 0;
    for (i = 0; s[i]; ++i) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
    if (!h) h = 1;
    idx = (unsigned)(h % SEEN_SLOTS);
    for (probe = 0; probe < SEEN_SLOTS; ++probe) {
        unsigned k = (idx + probe) % SEEN_SLOTS;
        if (g_seenHashes[k] == 0) {
            if (strcpy_s(g_seenLines[k], sizeof(g_seenLines[k]), s) != 0) return 1;
            g_seenHashes[k] = h;
            return 1;
        }
        if (g_seenHashes[k] == h && strcmp(g_seenLines[k], s) == 0) return 0;
    }
    return 1;   /* table full: treat as new */
}

static void sanitize_token(_Inout_updates_z_(n) char *s, size_t n)
{
    size_t i;
    if (!s || n == 0) return;
    s[n - 1] = 0;
    for (i = 0; s[i]; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c == 0x7f) s[i] = '_';
    }
}

static void pid_name(DWORD pid, _Out_writes_z_(n) char *out, size_t n)
{
    HANDLE h;
    if (!out || n == 0) return;
    out[0] = 0;
    if (pid == 0) { (void)strcpy_s(out, n, "System"); return; }
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        char path[MAX_PATH]; DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameA(h, 0, path, &sz)) {
            char *b = strrchr(path, '\\');
            (void)strncpy_s(out, n, b ? b + 1 : path, _TRUNCATE);
        }
        (void)CloseHandle(h);
    }
    if (!out[0]) (void)strcpy_s(out, n, "?");
    sanitize_token(out, n);
}

static void map_emit(_In_z_ const char *local, _In_z_ const char *remote, DWORD pid)
{
    char line[MAP_LINE_CAPACITY], name[64];
    int written;
    if (!local || !remote) return;
    pid_name(pid, name, sizeof(name));
    /* local remote PID name  (name may be "?" for protected/exited procs) */
    written = sprintf_s(line, sizeof(line), "%s %s %lu %s", local, remote,
                        (unsigned long)pid, name);
    if (written < 0 || (size_t)written >= sizeof(line)) return;
    EnterCriticalSection(&g_mapLock);
    if (g_map && seen_add(line) &&
        (fprintf(g_map, "%s\n", line) < 0 || fflush(g_map) != 0)) {
        (void)fclose(g_map);
        g_map = NULL;
    }
    LeaveCriticalSection(&g_mapLock);
}

static void fmt_v4(DWORD addr, DWORD port, _Out_writes_z_(n) char *out, size_t n)
{
    if (!out || n == 0) return;
    if (sprintf_s(out, n, "%u.%u.%u.%u:%u",
                  addr & 0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF,
                  ntohs((u_short)(port & 0xFFFF))) < 0) out[0] = 0;
}
static void fmt_v6(_In_reads_(16) const UCHAR *a, DWORD port,
                   _Out_writes_z_(n) char *out, size_t n)
{
    char ip[INET6_ADDRSTRLEN] = {0};
    struct in6_addr in6;
    if (!a || !out || n == 0) return;
    out[0] = 0;
    memcpy(&in6, a, 16);
    if (!inet_ntop(AF_INET6, &in6, ip, sizeof(ip))) return;
    if (sprintf_s(out, n, "[%s]:%u", ip,
                  ntohs((u_short)(port & 0xFFFF))) < 0) out[0] = 0;
}

static void poll_tcp_table(void)
{
    DWORD sz = 0, capacity;
    /* IPv4 */
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            == ERROR_INSUFFICIENT_BUFFER &&
        sz >= (DWORD)FIELD_OFFSET(MIB_TCPTABLE_OWNER_PID, table) &&
        sz <= MAX_TCP_TABLE_ALLOCATION) {
        PMIB_TCPTABLE_OWNER_PID t;
        capacity = sz;
        t = (PMIB_TCPTABLE_OWNER_PID)calloc(1, capacity);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, AF_INET,
                                    TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR &&
            sz <= capacity &&
            t->dwNumEntries <= (sz - FIELD_OFFSET(MIB_TCPTABLE_OWNER_PID, table)) /
                               sizeof(t->table[0])) {
            DWORD i;
            for (i = 0; i < t->dwNumEntries; ++i) {
                MIB_TCPROW_OWNER_PID *r = &t->table[i];
                char l[64], rem[64];
                if (!r->dwRemotePort) continue;      /* listeners: no peer */
                fmt_v4(r->dwLocalAddr,  r->dwLocalPort,  l,   sizeof(l));
                fmt_v4(r->dwRemoteAddr, r->dwRemotePort, rem, sizeof(rem));
                map_emit(l, rem, r->dwOwningPid);
            }
        }
        free(t);
    }
    /* IPv6 */
    sz = 0;
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
            == ERROR_INSUFFICIENT_BUFFER &&
        sz >= (DWORD)FIELD_OFFSET(MIB_TCP6TABLE_OWNER_PID, table) &&
        sz <= MAX_TCP_TABLE_ALLOCATION) {
        PMIB_TCP6TABLE_OWNER_PID t;
        capacity = sz;
        t = (PMIB_TCP6TABLE_OWNER_PID)calloc(1, capacity);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, AF_INET6,
                                    TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR &&
            sz <= capacity &&
            t->dwNumEntries <= (sz - FIELD_OFFSET(MIB_TCP6TABLE_OWNER_PID, table)) /
                               sizeof(t->table[0])) {
            DWORD i;
            for (i = 0; i < t->dwNumEntries; ++i) {
                MIB_TCP6ROW_OWNER_PID *r = &t->table[i];
                char l[64], rem[64];
                if (!r->dwRemotePort) continue;
                fmt_v6(r->ucLocalAddr,  r->dwLocalPort,  l,   sizeof(l));
                fmt_v6(r->ucRemoteAddr, r->dwRemotePort, rem, sizeof(rem));
                map_emit(l, rem, r->dwOwningPid);
            }
        }
        free(t);
    }
}

static DWORD WINAPI conmap_thread(_In_opt_ LPVOID p)
{
    (void)p;
    while (InterlockedCompareExchange(&g_running, 1, 1)) {
        poll_tcp_table();
        Sleep(200);
    }
    return 0;
}

/* ---- TDH property decode ------------------------------------------------ */
typedef struct { char name[64]; char val[256]; USHORT outType; } KV;
#define MAX_KV 64

static _Ret_maybenull_ LPCWSTR info_string(
    _In_reads_bytes_(infoSize) const TRACE_EVENT_INFO *info,
    ULONG infoSize, ULONG offset)
{
    const WCHAR *s;
    size_t i, count;
    if (!info || offset > infoSize || infoSize - offset < sizeof(WCHAR) ||
        offset % sizeof(WCHAR) != 0) return NULL;
    s = (const WCHAR *)((const BYTE *)info + offset);
    count = (infoSize - offset) / sizeof(WCHAR);
    for (i = 0; i < count; ++i) if (s[i] == L'\0') return s;
    return NULL;
}

static BOOL prop_length(_In_ PEVENT_RECORD ev,
                        _In_reads_bytes_(infoSize) PTRACE_EVENT_INFO info,
                        ULONG infoSize, USHORT i, _Out_ USHORT *length)
{
    PEVENT_PROPERTY_INFO p;
    if (!ev || !info || !length || i >= info->PropertyCount) return FALSE;
    p = &info->EventPropertyInfoArray[i];
    if (p->Flags & PropertyParamLength) {
        PROPERTY_DATA_DESCRIPTOR d; DWORD val = 0;
        LPCWSTR name;
        if (p->lengthPropertyIndex >= info->PropertyCount) return FALSE;
        name = info_string(info, infoSize,
            info->EventPropertyInfoArray[p->lengthPropertyIndex].NameOffset);
        if (!name) return FALSE;
        ZeroMemory(&d, sizeof(d));
        d.PropertyName = (ULONGLONG)(ULONG_PTR)name;
        d.ArrayIndex = ULONG_MAX;
        if (TdhGetProperty(ev, 0, NULL, 1, &d, sizeof(val), (PBYTE)&val) != ERROR_SUCCESS ||
            val > USHRT_MAX) return FALSE;
        *length = (USHORT)val;
        return TRUE;
    }
    *length = p->length;
    return TRUE;
}

static int decode_props(_In_ PEVENT_RECORD ev,
                        _In_reads_bytes_(infoSize) PTRACE_EVENT_INFO info,
                        ULONG infoSize, _Out_writes_(max) KV *kv, int max)
{
    USHORT i, pointerSize, remaining; PBYTE pData; int n = 0;
    size_t propertyBytes;
    if (!ev || !info || !kv || max <= 0 ||
        info->TopLevelPropertyCount > info->PropertyCount) return 0;
    if (info->PropertyCount >
        (SIZE_MAX - FIELD_OFFSET(TRACE_EVENT_INFO, EventPropertyInfoArray)) /
        sizeof(EVENT_PROPERTY_INFO)) return 0;
    propertyBytes = FIELD_OFFSET(TRACE_EVENT_INFO, EventPropertyInfoArray) +
                    (size_t)info->PropertyCount * sizeof(EVENT_PROPERTY_INFO);
    if (propertyBytes > infoSize) return 0;
    pointerSize = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    pData = (PBYTE)ev->UserData; remaining = ev->UserDataLength;
    if (remaining && !pData) return 0;
    for (i = 0; i < info->TopLevelPropertyCount && n < max; ++i) {
        PEVENT_PROPERTY_INFO p = &info->EventPropertyInfoArray[i];
        LPCWSTR name = info_string(info, infoSize, p->NameOffset);
        PEVENT_MAP_INFO map = NULL; DWORD mapSz = 0;
        USHORT plen, consumed = 0; ULONG bufBytes = 512; PWCHAR buf; TDHSTATUS fs;
        if (p->Flags & PropertyStruct) continue;
        if (!name) break;
        if (p->nonStructType.MapNameOffset) {
            LPCWSTR mn = info_string(info, infoSize, p->nonStructType.MapNameOffset);
            if (!mn) break;
            if (TdhGetEventMapInformation(ev, (PWSTR)mn, map, &mapSz) == ERROR_INSUFFICIENT_BUFFER) {
                if (!mapSz || mapSz > MAX_TDH_ALLOCATION) break;
                map = (PEVENT_MAP_INFO)calloc(1, mapSz);
                if (map && TdhGetEventMapInformation(ev, (PWSTR)mn, map, &mapSz) != ERROR_SUCCESS) { free(map); map = NULL; }
            }
        }
        if (!prop_length(ev, info, infoSize, i, &plen)) { free(map); break; }
        buf = (PWCHAR)calloc(1, bufBytes);
        if (!buf) { free(map); break; }
        fs = TdhFormatProperty(info, map, pointerSize, p->nonStructType.InType,
                               p->nonStructType.OutType, plen, remaining, pData, &bufBytes, buf, &consumed);
        if (fs == ERROR_INSUFFICIENT_BUFFER && bufBytes && bufBytes <= MAX_TDH_ALLOCATION) {
            PWCHAR nb = (PWCHAR)realloc(buf, bufBytes);
            if (nb) { buf = nb;
                ZeroMemory(buf, bufBytes);
                fs = TdhFormatProperty(info, map, pointerSize, p->nonStructType.InType,
                                       p->nonStructType.OutType, plen, remaining, pData, &bufBytes, buf, &consumed); }
        }
        if (fs == ERROR_SUCCESS && consumed <= remaining) {
            kv[n].name[0] = 0; kv[n].val[0] = 0;
            if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1,
                                     kv[n].name, sizeof(kv[n].name), NULL, NULL))
                (void)strcpy_s(kv[n].name, sizeof(kv[n].name), "?");
            if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buf, -1,
                                     kv[n].val, sizeof(kv[n].val), NULL, NULL))
                (void)strcpy_s(kv[n].val, sizeof(kv[n].val), "?");
            sanitize_token(kv[n].name, sizeof(kv[n].name));
            sanitize_token(kv[n].val, sizeof(kv[n].val));
            kv[n].outType = p->nonStructType.OutType; ++n;
            pData += consumed; remaining -= consumed;
        } else { free(buf); free(map); break; }
        free(buf); free(map);
    }
    return n;
}
/* No live rendering. The authoritative output is the post-capture packet decode
   (tls_group); conns.txt is fed by the TCP-table poller thread. This callback
   only serves the -v diagnostic dump. */
static void WINAPI on_event(_In_ PEVENT_RECORD ev)
{
    PTRACE_EVENT_INFO info = NULL; DWORD sz = 0; TDHSTATUS st;
    KV kv[MAX_KV]; int n, i, isSchannel, isTcpip;
    FILETIME fu, fl; SYSTEMTIME lt;

    if (!ev || !g_verbose) return;
    if (g_filterPid && ev->EventHeader.ProcessId != g_filterPid) return;
    isSchannel = IsEqualGUID(ev->EventHeader.ProviderId, SchannelGuid);
    isTcpip    = IsEqualGUID(ev->EventHeader.ProviderId, TcpipGuid);

    st = TdhGetEventInformation(ev, 0, NULL, info, &sz);
    if (st == ERROR_INSUFFICIENT_BUFFER &&
        sz >= sizeof(TRACE_EVENT_INFO) && sz <= MAX_TDH_ALLOCATION) {
        info = (PTRACE_EVENT_INFO)calloc(1, sz);
        st = info ? TdhGetEventInformation(ev, 0, NULL, info, &sz) : ERROR_OUTOFMEMORY;
    }
    if (st != ERROR_SUCCESS || !info) { free(info); return; }
    ZeroMemory(kv, sizeof(kv));
    n = decode_props(ev, info, sz, kv, MAX_KV);

    fu.dwLowDateTime = ev->EventHeader.TimeStamp.LowPart;
    fu.dwHighDateTime = ev->EventHeader.TimeStamp.HighPart;
    FileTimeToLocalFileTime(&fu,&fl); FileTimeToSystemTime(&fl,&lt);
    printf("%02u:%02u:%02u.%03u  PID=%lu  %s  event=%u\n",
           lt.wHour,lt.wMinute,lt.wSecond,lt.wMilliseconds, ev->EventHeader.ProcessId,
           isSchannel?"Schannel":isTcpip?"TCPIP":"?", ev->EventHeader.EventDescriptor.Id);
    for (i=0;i<n;++i) printf("    %-22s = %s\n", kv[i].name, kv[i].val);
    printf("\n");
    free(info);
}

static BOOL WINAPI ctrl_handler(DWORD type)
{
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        InterlockedExchange(&g_running, 0);
        if (InterlockedCompareExchange(&g_sessionStarted, 1, 1) && g_props)
            (void)ControlTraceW(g_session, g_sessionName, g_props,
                                EVENT_TRACE_CONTROL_STOP);
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL parse_pid(_In_z_ const char *text, _Out_ DWORD *pid)
{
    char *end;
    unsigned long value;
    if (!text || !pid || !*text) return FALSE;
    errno = 0;
    end = NULL;
    value = strtoul(text, &end, 10);
    if (errno == ERANGE || end == text || !end || *end || value == 0 ||
        value > MAXDWORD) return FALSE;
    *pid = (DWORD)value;
    return TRUE;
}

static _Ret_maybenull_ FILE *open_map_file(void)
{
    WCHAR path[32768], *slash;
    DWORD length;
    HANDLE file;
    int descriptor;
    FILE *stream = NULL;

    length = GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
    if (!length || length >= ARRAYSIZE(path)) return NULL;
    path[length] = L'\0';
    slash = wcsrchr(path, L'\\');
    if (!slash || FAILED(StringCchCopyW(slash + 1,
        ARRAYSIZE(path) - (size_t)(slash + 1 - path), L"conns.txt"))) return NULL;

    file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;
    descriptor = _open_osfhandle((intptr_t)file, _O_TEXT);
    if (descriptor == -1) { (void)CloseHandle(file); return NULL; }
    stream = _fdopen(descriptor, "w");
    if (!stream) {
        (void)_close(descriptor);
        return NULL;
    }
    return stream;
}

int main(_In_ int argc, _In_reads_(argc) char **argv)
{
    ULONG bufSize, rc;
    EVENT_TRACE_LOGFILEW log;
    int a, exitCode = EXIT_FAILURE;
    BOOL lockInitialized = FALSE, handlerInstalled = FALSE;
    HANDLE hcm = NULL;

    for (a = 1; a < argc; ++a) {
        if (_stricmp(argv[a], "-v") == 0) g_verbose = 1;
        else if (_stricmp(argv[a], "-p") == 0) {
            if (a + 1 >= argc || !parse_pid(argv[++a], &g_filterPid)) {
                fprintf(stderr, "Usage: schannel_etw [-v] [-p PID | PID]\n");
                return EXIT_FAILURE;
            }
        } else if (!parse_pid(argv[a], &g_filterPid)) {
            fprintf(stderr, "Usage: schannel_etw [-v] [-p PID | PID]\n");
            return EXIT_FAILURE;
        }
    }

    if (FAILED(StringCchPrintfW(g_sessionName, ARRAYSIZE(g_sessionName),
                                L"SchannelRT_Consumer_%lu",
                                (unsigned long)GetCurrentProcessId()))) {
        fprintf(stderr, "Unable to construct the ETW session name.\n");
        goto cleanup;
    }

    InitializeCriticalSection(&g_mapLock);
    lockInitialized = TRUE;
    g_map = open_map_file();
    if (!g_map) {
        fprintf(stderr, "Unable to securely create conns.txt: %lu\n",
                (unsigned long)GetLastError());
        goto cleanup;
    }
    hcm = CreateThread(NULL, 0, conmap_thread, NULL, 0, NULL);
    if (!hcm) {
        fprintf(stderr, "CreateThread failed: %lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }

    bufSize = sizeof(EVENT_TRACE_PROPERTIES) +
              (ULONG)(ARRAYSIZE(g_sessionName) * sizeof(WCHAR));
    g_props = (PEVENT_TRACE_PROPERTIES)calloc(1, bufSize);
    if (!g_props) { fprintf(stderr, "Out of memory.\n"); goto cleanup; }
    g_props->Wnode.BufferSize = bufSize;
    g_props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_props->Wnode.ClientContext = 2;
    g_props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    rc = StartTraceW(&g_session, g_sessionName, g_props);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "StartTrace failed: %lu%s\n", rc, rc==ERROR_ACCESS_DENIED?" (run elevated)":"");
        goto cleanup;
    }
    InterlockedExchange(&g_sessionStarted, 1);
    rc = EnableTraceEx2(g_session, &SchannelGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
    if (rc != ERROR_SUCCESS) { fprintf(stderr, "Enable Schannel failed: %lu\n", rc); goto cleanup; }
    rc = EnableTraceEx2(g_session, &TcpipGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (rc != ERROR_SUCCESS) { fprintf(stderr, "Enable TCPIP failed: %lu\n", rc); goto cleanup; }

    if (!SetConsoleCtrlHandler(ctrl_handler, TRUE)) {
        fprintf(stderr, "SetConsoleCtrlHandler failed: %lu\n",
                (unsigned long)GetLastError());
        goto cleanup;
    }
    handlerInstalled = TRUE;

    ZeroMemory(&log, sizeof(log));
    log.LoggerName = g_sessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = on_event;
    g_trace = OpenTraceW(&log);
    if (g_trace == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        fprintf(stderr, "OpenTrace failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (g_verbose)
        printf("== verbose: dumping Schannel + TCPIP events (Ctrl+C to stop) ==\n\n");
    else
        printf("Listening for Schannel events (capturing to conns.txt)...\n"
               "Leave this open. When done, run stop-sch.ps1 in the parent window (it stops this), or press Ctrl+C here.\n");

    rc = ProcessTrace(&g_trace, 1, NULL, NULL);
    if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED &&
        rc != ERROR_CTX_CLOSE_PENDING) fprintf(stderr, "ProcessTrace: %lu\n", rc);
    else exitCode = EXIT_SUCCESS;

cleanup:
    InterlockedExchange(&g_running, 0);
    if (handlerInstalled) (void)SetConsoleCtrlHandler(ctrl_handler, FALSE);
    if (InterlockedExchange(&g_sessionStarted, 0) && g_props)
        (void)ControlTraceW(g_session, g_sessionName, g_props, EVENT_TRACE_CONTROL_STOP);
    if (g_trace != (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        (void)CloseTrace(g_trace);
        g_trace = (TRACEHANDLE)INVALID_HANDLE_VALUE;
    }
    if (hcm) {
        (void)WaitForSingleObject(hcm, INFINITE);
        (void)CloseHandle(hcm);
    }
    if (g_map) { (void)fclose(g_map); g_map = NULL; }
    free(g_props); g_props = NULL;
    if (lockInitialized) DeleteCriticalSection(&g_mapLock);
    return exitCode;
}
