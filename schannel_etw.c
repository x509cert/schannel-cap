/*
 * schannel_etw.c  --  TLS connection-map writer + ETW listener (no injection)
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
 *   cl /nologo /O2 /MT /W3 /D_CRT_SECURE_NO_WARNINGS schannel_etw.c ^
 *      /link tdh.lib advapi32.lib iphlpapi.lib ws2_32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define SESSION_NAME L"SchannelRT_Consumer"

static const GUID SchannelGuid =
    { 0x1F678132,0x5938,0x4686,{0x9F,0xDC,0xC8,0xFF,0x68,0xF1,0x5C,0x85} };
static const GUID TcpipGuid =
    { 0x2F07E2EE,0x15DB,0x40F1,{0x90,0xEF,0x9D,0x7B,0xA2,0x82,0x18,0x8A} };

static TRACEHANDLE             g_session = 0;
static TRACEHANDLE             g_trace   = (TRACEHANDLE)INVALID_HANDLE_VALUE;
static PEVENT_TRACE_PROPERTIES g_props   = NULL;
static int                     g_verbose = 0;
static DWORD                   g_filterPid = 0;
static volatile LONG           g_running = 1;

/* ---- connection map (conns.txt) writer ---------------------------------- */
static FILE            *g_map = NULL;
static CRITICAL_SECTION g_mapLock;
#define SEEN_SLOTS 32768
static unsigned long long g_seen[SEEN_SLOTS];   /* open-addressed hash of lines */

static int seen_add(const char *s)   /* returns 1 if newly added, 0 if present */
{
    unsigned long long h = 1469598103934665603ULL;
    size_t i; unsigned idx, probe;
    for (i = 0; s[i]; ++i) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
    if (!h) h = 1;
    idx = (unsigned)(h % SEEN_SLOTS);
    for (probe = 0; probe < SEEN_SLOTS; ++probe) {
        unsigned k = (idx + probe) % SEEN_SLOTS;
        if (g_seen[k] == 0)  { g_seen[k] = h; return 1; }
        if (g_seen[k] == h)  return 0;
    }
    return 1;   /* table full: treat as new */
}

static void pid_name(DWORD pid, char *out, size_t n)
{
    HANDLE h;
    out[0] = 0;
    if (pid == 0) { strncpy(out, "System", n-1); out[n-1]=0; return; }
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        char path[MAX_PATH]; DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameA(h, 0, path, &sz)) {
            char *b = strrchr(path, '\\');
            strncpy(out, b ? b + 1 : path, n-1); out[n-1] = 0;
        }
        CloseHandle(h);
    }
    if (!out[0]) { strncpy(out, "?", n-1); out[n-1] = 0; }
}

static void map_emit(const char *local, const char *remote, DWORD pid)
{
    char line[224], name[64];
    pid_name(pid, name, sizeof(name));
    /* local remote PID name  (name may be "?" for protected/exited procs) */
    _snprintf(line, sizeof(line), "%s %s %lu %s", local, remote, pid, name);
    line[sizeof(line)-1] = 0;
    EnterCriticalSection(&g_mapLock);
    if (g_map && seen_add(line)) { fprintf(g_map, "%s\n", line); fflush(g_map); }
    LeaveCriticalSection(&g_mapLock);
}

static void fmt_v4(DWORD addr, DWORD port, char *out, size_t n)
{
    _snprintf(out, n, "%u.%u.%u.%u:%u",
              addr & 0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF,
              ntohs((u_short)(port & 0xFFFF)));
    out[n-1] = 0;
}
static void fmt_v6(const UCHAR *a, DWORD port, char *out, size_t n)
{
    char ip[INET6_ADDRSTRLEN] = {0};
    struct in6_addr in6;
    memcpy(&in6, a, 16);
    inet_ntop(AF_INET6, &in6, ip, sizeof(ip));
    _snprintf(out, n, "[%s]:%u", ip, ntohs((u_short)(port & 0xFFFF)));
    out[n-1] = 0;
}

static void poll_tcp_table(void)
{
    DWORD sz = 0;
    /* IPv4 */
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            == ERROR_INSUFFICIENT_BUFFER) {
        PMIB_TCPTABLE_OWNER_PID t = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
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
            == ERROR_INSUFFICIENT_BUFFER) {
        PMIB_TCP6TABLE_OWNER_PID t = (PMIB_TCP6TABLE_OWNER_PID)malloc(sz);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
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

static DWORD WINAPI conmap_thread(LPVOID p)
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

static USHORT prop_length(PEVENT_RECORD ev, PTRACE_EVENT_INFO info, USHORT i)
{
    PEVENT_PROPERTY_INFO p = &info->EventPropertyInfoArray[i];
    if (p->Flags & PropertyParamLength) {
        PROPERTY_DATA_DESCRIPTOR d; DWORD val = 0;
        d.PropertyName = (ULONGLONG)((PBYTE)info +
                          info->EventPropertyInfoArray[p->lengthPropertyIndex].NameOffset);
        d.ArrayIndex = ULONG_MAX;
        if (TdhGetProperty(ev, 0, NULL, 1, &d, sizeof(val), (PBYTE)&val) == ERROR_SUCCESS)
            return (USHORT)val;
        return 0;
    }
    return p->length;
}

static int decode_props(PEVENT_RECORD ev, PTRACE_EVENT_INFO info, KV *kv, int max)
{
    USHORT i, pointerSize, remaining; PBYTE pData; int n = 0;
    pointerSize = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    pData = (PBYTE)ev->UserData; remaining = ev->UserDataLength;
    for (i = 0; i < info->TopLevelPropertyCount && n < max; ++i) {
        PEVENT_PROPERTY_INFO p = &info->EventPropertyInfoArray[i];
        LPWSTR name = (LPWSTR)((PBYTE)info + p->NameOffset);
        PEVENT_MAP_INFO map = NULL; DWORD mapSz = 0;
        USHORT plen, consumed = 0; ULONG bufBytes = 512; PWCHAR buf; TDHSTATUS fs;
        if (p->Flags & PropertyStruct) continue;
        if (p->nonStructType.MapNameOffset) {
            LPWSTR mn = (LPWSTR)((PBYTE)info + p->nonStructType.MapNameOffset);
            if (TdhGetEventMapInformation(ev, mn, map, &mapSz) == ERROR_INSUFFICIENT_BUFFER) {
                map = (PEVENT_MAP_INFO)malloc(mapSz);
                if (map && TdhGetEventMapInformation(ev, mn, map, &mapSz) != ERROR_SUCCESS) { free(map); map = NULL; }
            }
        }
        plen = prop_length(ev, info, i);
        buf = (PWCHAR)malloc(bufBytes);
        if (!buf) { free(map); break; }
        fs = TdhFormatProperty(info, map, pointerSize, p->nonStructType.InType,
                               p->nonStructType.OutType, plen, remaining, pData, &bufBytes, buf, &consumed);
        if (fs == ERROR_INSUFFICIENT_BUFFER) {
            PWCHAR nb = (PWCHAR)realloc(buf, bufBytes);
            if (nb) { buf = nb;
                fs = TdhFormatProperty(info, map, pointerSize, p->nonStructType.InType,
                                       p->nonStructType.OutType, plen, remaining, pData, &bufBytes, buf, &consumed); }
        }
        if (fs == ERROR_SUCCESS) {
            WideCharToMultiByte(CP_UTF8, 0, name, -1, kv[n].name, sizeof(kv[n].name), NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, buf,  -1, kv[n].val,  sizeof(kv[n].val),  NULL, NULL);
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
static void WINAPI on_event(PEVENT_RECORD ev)
{
    PTRACE_EVENT_INFO info = NULL; DWORD sz = 0; TDHSTATUS st;
    KV kv[MAX_KV]; int n, i, isSchannel, isTcpip;
    FILETIME fu, fl; SYSTEMTIME lt;

    if (!g_verbose) return;
    if (g_filterPid && ev->EventHeader.ProcessId != g_filterPid) return;
    isSchannel = IsEqualGUID(&ev->EventHeader.ProviderId, &SchannelGuid);
    isTcpip    = IsEqualGUID(&ev->EventHeader.ProviderId, &TcpipGuid);

    st = TdhGetEventInformation(ev, 0, NULL, info, &sz);
    if (st == ERROR_INSUFFICIENT_BUFFER) {
        info = (PTRACE_EVENT_INFO)malloc(sz);
        st = info ? TdhGetEventInformation(ev, 0, NULL, info, &sz) : ERROR_OUTOFMEMORY;
    }
    if (st != ERROR_SUCCESS || !info) { free(info); return; }
    n = decode_props(ev, info, kv, MAX_KV);

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
    (void)type;
    InterlockedExchange(&g_running, 0);
    if (g_props) ControlTraceW(g_session, SESSION_NAME, g_props, EVENT_TRACE_CONTROL_STOP);
    if (g_trace != (TRACEHANDLE)INVALID_HANDLE_VALUE) CloseTrace(g_trace);
    return TRUE;
}

int main(int argc, char **argv)
{
    ULONG bufSize, rc; EVENT_TRACE_LOGFILEW log; int a; HANDLE hcm;

    for (a = 1; a < argc; ++a) {
        if (_stricmp(argv[a], "-v") == 0) g_verbose = 1;
        else if (_stricmp(argv[a], "-p") == 0 && a + 1 < argc) g_filterPid = (DWORD)strtoul(argv[++a], NULL, 10);
        else { DWORD v = (DWORD)strtoul(argv[a], NULL, 10); if (v) g_filterPid = v; }
    }

    InitializeCriticalSection(&g_mapLock);
    {   /* conns.txt lives next to this exe, not the (possibly System32) CWD */
        char path[MAX_PATH], *slash;
        DWORD gm = GetModuleFileNameA(NULL, path, sizeof(path));
        if (gm && gm < sizeof(path) && (slash = strrchr(path, '\\')) != NULL) {
            strcpy(slash + 1, "conns.txt");
            g_map = fopen(path, "w");
        }
        if (!g_map) g_map = fopen("conns.txt", "w");   /* fallback: CWD */
    }
    hcm = CreateThread(NULL, 0, conmap_thread, NULL, 0, NULL);

    bufSize = sizeof(EVENT_TRACE_PROPERTIES) +
              (ULONG)((wcslen(SESSION_NAME) + 1) * sizeof(WCHAR));
    g_props = (PEVENT_TRACE_PROPERTIES)calloc(1, bufSize);
    if (!g_props) return 1;
    g_props->Wnode.BufferSize = bufSize;
    g_props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_props->Wnode.ClientContext = 2;
    g_props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    rc = StartTraceW(&g_session, SESSION_NAME, g_props);
    if (rc == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, SESSION_NAME, g_props, EVENT_TRACE_CONTROL_STOP);
        g_props->Wnode.BufferSize = bufSize; g_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        rc = StartTraceW(&g_session, SESSION_NAME, g_props);
    }
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "StartTrace failed: %lu%s\n", rc, rc==ERROR_ACCESS_DENIED?" (run elevated)":"");
        return 1;
    }
    EnableTraceEx2(g_session, &SchannelGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
    EnableTraceEx2(g_session, &TcpipGuid,    EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    ZeroMemory(&log, sizeof(log));
    log.LoggerName = (LPWSTR)SESSION_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = on_event;
    g_trace = OpenTraceW(&log);
    if (g_trace == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        fprintf(stderr, "OpenTrace failed: %lu\n", GetLastError());
        ControlTraceW(g_session, SESSION_NAME, g_props, EVENT_TRACE_CONTROL_STOP); return 1;
    }

    if (g_verbose)
        printf("== verbose: dumping Schannel + TCPIP events (Ctrl+C to stop) ==\n\n");
    else
        printf("Listening for Schannel events (capturing to conns.txt)...\n"
               "Leave this open. When done, run stop-sch.ps1 in the parent window (it stops this), or press Ctrl+C here.\n");

    rc = ProcessTrace(&g_trace, 1, NULL, NULL);
    if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED) fprintf(stderr, "ProcessTrace: %lu\n", rc);

    InterlockedExchange(&g_running, 0);
    if (hcm) { WaitForSingleObject(hcm, 500); CloseHandle(hcm); }
    ControlTraceW(g_session, SESSION_NAME, g_props, EVENT_TRACE_CONTROL_STOP);
    if (g_map) fclose(g_map);
    return 0;
}
