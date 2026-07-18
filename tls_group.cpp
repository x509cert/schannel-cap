/*
 * tls_group.cpp  --  extract the NEGOTIATED TLS group + cipher from ServerHello
 *
 * Reads a pcapng capture (pktmon / etl2pcapng / Wireshark native) and, for each
 * TLS ServerHello, prints:
 *     src:port -> dst:port   cipher=0xXXXX(name)   group=0xXXXX(name)
 *
 * The ServerHello is plaintext even in TLS 1.3 and its key_share extension (51)
 * carries the SELECTED group -- that's the ground truth for what was negotiated,
 * including PQC hybrids like X25519MLKEM768 (0x11EC).
 *
 * Capture on localhost (Kestrel) -- pktmon sees loopback, netsh/NDIS do not:
 *     pktmon start --capture --pkt-size 0 -f C:\temp\tls.etl
 *     ...run the handshake...
 *     pktmon stop
 *     pktmon etl2pcap C:\temp\tls.etl -o C:\temp\tls.pcapng   (writes pcapng)
 *     tls_group.exe C:\temp\tls.pcapng
 *
 * Scope: parses Ethernet/NULL/RAW link layers, IPv4/IPv6, TCP, and a ServerHello
 * that fits in one segment (true in practice -- ServerHello is small; only the
 * ML-KEM *ClientHello* is large). No TCP reassembly.
 *
 * BUILD:  cl /nologo /O2 /MT /W4 /GS /guard:cf /Qspectre /sdl ^
 *         /std:c++20 /permissive- /EHsc /D_CRT_SECURE_NO_WARNINGS ^
 *         tls_group.cpp /link /DYNAMICBASE /NXCOMPAT /guard:cf
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int g_swap = 0;                    /* pcapng section byte-order */
static uint16_t g_linktype = 1;           /* from first IDB (1 = Ethernet) */
static uint64_t g_tsDenom = 1000000;      /* pcapng ticks/sec (if_tsresol; default us) */
static uint64_t g_pktTicks = 0;           /* current packet timestamp (ticks) */

static uint16_t rd16(const uint8_t *p){ return g_swap ? (uint16_t)(p[0]<<8|p[1]) : (uint16_t)(p[1]<<8|p[0]); }
static uint32_t rd32(const uint8_t *p){ return g_swap ? ((uint32_t)p[0]<<24|p[1]<<16|p[2]<<8|p[3])
                                                       : ((uint32_t)p[3]<<24|p[2]<<16|p[1]<<8|p[0]); }
/* big-endian readers for network/TLS fields */
static uint16_t be16(const uint8_t *p){ return (uint16_t)(p[0]<<8 | p[1]); }
static uint32_t be24(const uint8_t *p){ return (uint32_t)(p[0]<<16 | p[1]<<8 | p[2]); }

/* format the current packet's pcapng timestamp as local HH:MM:SS.mmm */
static void fmt_time(char *out, size_t n)
{
    uint64_t sec, usec;
    ULARGE_INTEGER u;
    FILETIME ft, lf; SYSTEMTIME st;
    if (!g_pktTicks || !g_tsDenom) { _snprintf(out, n, "--:--:--.---"); out[n-1]=0; return; }
    sec  = g_pktTicks / g_tsDenom;
    usec = (g_pktTicks % g_tsDenom) * 1000000ULL / g_tsDenom;
    u.QuadPart = 116444736000000000ULL + sec * 10000000ULL + usec * 10ULL; /* Unix->FILETIME */
    ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart;
    FileTimeToLocalFileTime(&ft, &lf); FileTimeToSystemTime(&lf, &st);
    _snprintf(out, n, "%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    out[n-1] = 0;
}

static const char *cipher_name(uint16_t c){
    switch (c){
    case 0x1301: return "TLS_AES_128_GCM_SHA256";
    case 0x1302: return "TLS_AES_256_GCM_SHA384";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    case 0xC02B: return "ECDHE_ECDSA_AES128_GCM_SHA256";
    case 0xC02F: return "ECDHE_RSA_AES128_GCM_SHA256";
    case 0xC030: return "ECDHE_RSA_AES256_GCM_SHA384";
    default:     return "?";
    }
}
static const char *group_name(uint16_t g){
    switch (g){
    case 0x0017: return "secp256r1";
    case 0x0018: return "secp384r1";
    case 0x0019: return "secp521r1";
    case 0x001D: return "x25519";
    case 0x001E: return "x448";
    case 0x11EC: return "X25519MLKEM768";       /* PQC hybrid */
    case 0x11EB: return "SecP256r1MLKEM768";
    case 0x11ED: return "SecP384r1MLKEM1024";
    case 0x6399: return "X25519Kyber768Draft00";
    default:     return "?";
    }
}

static const char *ver_name(uint16_t v){
    switch (v){
    case 0x0304: return "TLS1.3";
    case 0x0303: return "TLS1.2";
    case 0x0302: return "TLS1.1";
    case 0x0301: return "TLS1.0";
    case 0x0300: return "SSL3.0";
    default:     return "?";
    }
}

/* classification for coloring: hybrid / pqc get highlighted green */
static const char *group_class(uint16_t g){
    switch (g){
    case 0x11EC: case 0x11EB: case 0x11ED: case 0x6399: return "hybrid";
    /* pure ML-KEM groups would return "pqc" here once codepoints are assigned */
    case 0x0017: case 0x0018: case 0x0019: case 0x001D: case 0x001E: return "classical";
    case 0x0000: return "none";
    default:     return "classical";
    }
}

static int g_csv = 0;   /* -csv: emit CSV for the PowerShell table */

/* ---- optional 4-tuple -> PID/name map loaded from conns.txt ------------- */
typedef struct { char local[64]; char remote[64]; unsigned long pid; char proc[64]; } MapEnt;
static MapEnt *g_map = NULL;
static int     g_mapN = 0, g_mapCap = 0;
static char    g_filterIp[64] = "";     /* if set, only lines involving this IP */

/* does endpoint "ip:port" have IP == g_filterIp ? (prefix up to ':') */
static int ep_ip_is(const char *ep)
{
    size_t n = strlen(g_filterIp);
    return n && strncmp(ep, g_filterIp, n) == 0 && ep[n] == ':';
}

static void map_load(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256];
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        MapEnt e;
        e.proc[0] = 0;
        /* local remote PID [name] -- name optional for back-compat */
        if (sscanf(line, "%63s %63s %lu %63s", e.local, e.remote, &e.pid, e.proc) >= 3) {
            if (g_mapN == g_mapCap) {
                g_mapCap = g_mapCap ? g_mapCap * 2 : 256;
                g_map = (MapEnt *)realloc(g_map, g_mapCap * sizeof(MapEnt));
                if (!g_map) { fclose(f); return; }
            }
            g_map[g_mapN++] = e;
        }
    }
    fclose(f);
}

/* ServerHello sender = src. Prefer the server's own socket (local==src);
   fall back to the client's socket (local==dst). Returns PID or 0, sets
   side and (if non-NULL) proc name. */
static unsigned long map_lookup(const char *src, const char *dst,
                                const char **side, const char **proc)
{
    int i;
    for (i = 0; i < g_mapN; ++i)
        if (strcmp(g_map[i].local, src) == 0 && strcmp(g_map[i].remote, dst) == 0) {
            *side = "srv"; if (proc) *proc = g_map[i].proc; return g_map[i].pid; }
    for (i = 0; i < g_mapN; ++i)
        if (strcmp(g_map[i].local, dst) == 0 && strcmp(g_map[i].remote, src) == 0) {
            *side = "cli"; if (proc) *proc = g_map[i].proc; return g_map[i].pid; }
    *side = "?"; if (proc) *proc = "";
    return 0;
}

/* Parse a ServerHello body (after handshake type+len). Emits cipher+group. */
static void parse_server_hello(const uint8_t *hs, uint32_t len,
                               const char *src, const char *dst)
{
    uint32_t o = 0;
    uint16_t cipher, extTotal, selGroup = 0, selVer = 0, legacyVer;
    uint8_t  sidLen;

    if (len < 2 + 32 + 1) return;
    legacyVer = be16(hs);                     /* legacy_version (0x0303 in 1.3) */
    o += 2;                                   /* legacy_version */
    o += 32;                                  /* random */
    sidLen = hs[o]; o += 1 + sidLen;          /* session_id */
    if (o + 2 + 1 + 2 > len) return;
    cipher = be16(hs + o); o += 2;            /* cipher_suite */
    o += 1;                                   /* compression */
    extTotal = be16(hs + o); o += 2;          /* extensions length */
    if (o + extTotal > len) extTotal = (uint16_t)(len - o);

    { uint32_t end = o + extTotal;
      while (o + 4 <= end) {
        uint16_t et = be16(hs + o); uint16_t el = be16(hs + o + 2); o += 4;
        if (o + el > end) break;
        if (et == 51 && el >= 2) selGroup = be16(hs + o);   /* key_share -> group */
        if (et == 43 && el >= 2) selVer   = be16(hs + o);   /* supported_versions */
        o += el;
      }
    }

    if (g_filterIp[0] && !ep_ip_is(src) && !ep_ip_is(dst)) return;

    { const char *side = "?", *proc = "";
      char ts[16];
      uint16_t ver = selVer ? selVer : legacyVer;   /* 1.3 lives in the extension */
      unsigned long pid = g_mapN ? map_lookup(src, dst, &side, &proc) : 0;
      fmt_time(ts, sizeof(ts));

      if (g_csv) {
          char pidbuf[16], grp[64], cip[64], pname[64];
          const char *gn = selGroup ? group_name(selGroup) : "none";
          if (pid) _snprintf(pidbuf, sizeof(pidbuf), "%lu", pid); else strcpy(pidbuf, "?");
          /* Process: image name if known, else fall back to the PID */
          if (proc && proc[0] && strcmp(proc, "?") != 0) { strncpy(pname, proc, sizeof(pname)-1); pname[sizeof(pname)-1]=0; }
          else { strncpy(pname, pidbuf, sizeof(pname)-1); pname[sizeof(pname)-1]=0; }
          /* group: name if known, else raw hex */
          if (strcmp(gn, "?") == 0) _snprintf(grp, sizeof(grp), "0x%04X", selGroup);
          else { strncpy(grp, gn, sizeof(grp)-1); grp[sizeof(grp)-1] = 0; }
          /* cipher: name if known, else raw hex */
          { const char *cn = cipher_name(cipher);
            if (strcmp(cn, "?") == 0) _snprintf(cip, sizeof(cip), "0x%04X", cipher);
            else { strncpy(cip, cn, sizeof(cip)-1); cip[sizeof(cip)-1] = 0; } }
          /* Time,PID,Process,Side,Source,Dest,Version,Cipher,Group,Class
             ServerHello sender is the server; emit as client(dst) -> server(src). */
          printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
                 ts, pidbuf, pname, side, dst, src, ver_name(ver),
                 cip, grp, group_class(selGroup));
      } else {
          const char *gn = selGroup ? group_name(selGroup) : "none";
          const char *cn = cipher_name(cipher);
          char grp[64], cip[64];
          if (strcmp(gn, "?") == 0) _snprintf(grp, sizeof(grp), "0x%04X", selGroup);
          else { strncpy(grp, gn, sizeof(grp)-1); grp[sizeof(grp)-1] = 0; }
          if (strcmp(cn, "?") == 0) _snprintf(cip, sizeof(cip), "0x%04X", cipher);
          else { strncpy(cip, cn, sizeof(cip)-1); cip[sizeof(cip)-1] = 0; }
          printf("%s  ", ts);
          if (proc && proc[0] && strcmp(proc, "?") != 0) printf("%-20s(%s)  ", proc, side);
          else if (pid) printf("pid=%lu(%s)  ", pid, side);
          else if (g_mapN) printf("pid=?       ");
          printf("%-8s %-21s -> %-21s  cipher=%s  group=%s\n",
                 ver_name(ver), dst, src, cip, grp);
      }
    }
}

/* Walk TLS records in a TCP payload; handle ServerHello. */
static void scan_tls(const uint8_t *p, uint32_t len, const char *src, const char *dst)
{
    uint32_t o = 0;
    while (o + 5 <= len) {
        uint8_t  ct  = p[o];
        uint16_t rl  = be16(p + o + 3);
        if (ct != 22) return;                 /* not handshake -> stop */
        if (o + 5 + rl > len) return;
        { const uint8_t *hs = p + o + 5;
          if (rl >= 4 && hs[0] == 2) {        /* handshake type 2 = ServerHello */
              uint32_t hlen = be24(hs + 1);
              if (4 + hlen <= rl) parse_server_hello(hs + 4, hlen, src, dst);
          }
        }
        o += 5 + rl;
    }
}

static void handle_packet(const uint8_t *p, uint32_t caplen)
{
    uint32_t o = 0;
    uint8_t  ipVer, proto;
    char src[46] = "?", dst[46] = "?", srcep[64], dstep[64];
    uint16_t ethType, sport, dport, ihl, thl;

    /* link layer */
    if (g_linktype == 1) {                    /* Ethernet */
        if (caplen < 14) return;
        ethType = be16(p + 12); o = 14;
        while (ethType == 0x8100 && o + 4 <= caplen) { ethType = be16(p + o + 2); o += 4; } /* VLAN */
        if (ethType != 0x0800 && ethType != 0x86DD) return;
        ipVer = (ethType == 0x0800) ? 4 : 6;
    } else if (g_linktype == 0) {             /* NULL/loopback: 4-byte family */
        if (caplen < 4) return;
        { uint32_t fam = rd32(p); o = 4; ipVer = (fam == 2) ? 4 : 6; }
    } else if (g_linktype == 101) {           /* RAW IP */
        ipVer = (p[0] >> 4) & 0xF;
    } else return;

    if (ipVer == 4) {
        if (o + 20 > caplen) return;
        ihl = (uint16_t)((p[o] & 0x0F) * 4);
        proto = p[o + 9];
        sprintf(src, "%u.%u.%u.%u", p[o+12], p[o+13], p[o+14], p[o+15]);
        sprintf(dst, "%u.%u.%u.%u", p[o+16], p[o+17], p[o+18], p[o+19]);
        o += ihl;
    } else {                                  /* IPv6 (no ext-header handling) */
        if (o + 40 > caplen) return;
        proto = p[o + 6];
        { int k; char *q = src; for (k=0;k<16;k+=2){ q += sprintf(q, k?":%02x%02x":"%02x%02x", p[o+8+k], p[o+9+k]); }
          q = dst; for (k=0;k<16;k+=2){ q += sprintf(q, k?":%02x%02x":"%02x%02x", p[o+24+k], p[o+25+k]); } }
        o += 40;
    }
    if (proto != 6) return;                   /* TCP only */
    if (o + 20 > caplen) return;

    sport = be16(p + o); dport = be16(p + o + 2);
    thl = (uint16_t)(((p[o + 12] >> 4) & 0xF) * 4);
    o += thl;
    if (o > caplen) return;

    sprintf(srcep, "%s:%u", src, sport);
    sprintf(dstep, "%s:%u", dst, dport);
    scan_tls(p + o, caplen - o, srcep, dstep);
}

int main(int argc, char **argv)
{
    FILE *f;
    uint8_t hdr[12];
    long fsize;
    uint8_t *body;
    const char *argv0_pcap = NULL;
    long total_bytes = 0;
    int  last_pct = -1;

    { int i, pos = 0;
      for (i = 1; i < argc; ++i) {
          if (strcmp(argv[i], "-csv") == 0) { g_csv = 1; continue; }
          if (pos == 0) argv0_pcap = argv[i];
          else if (pos == 1) map_load(argv[i]);
          else if (pos == 2) { strncpy(g_filterIp, argv[i], sizeof(g_filterIp)-1); g_filterIp[sizeof(g_filterIp)-1] = 0; }
          ++pos;
      }
      if (!argv0_pcap) { fprintf(stderr, "usage: tls_group <capture.pcapng> [conns.txt] [filter-ip] [-csv]\n"); return 2; }
    }
    f = fopen(argv0_pcap, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv0_pcap); return 1; }

    /* total size for the progress counter */
    fseek(f, 0, SEEK_END); { long tsz = ftell(f); total_bytes = tsz > 0 ? tsz : 0; } fseek(f, 0, SEEK_SET);

    if (g_csv)
        printf("Time,PID,Process,Side,Source,Dest,Version,Cipher,Group,Class\n");
    else
        printf("negotiated groups from ServerHello in %s%s%s%s:\n\n",
               argv0_pcap, g_mapN ? " (PID via conns.txt)" : "",
               g_filterIp[0] ? " filtered to " : "", g_filterIp);

    /* pcapng: iterate blocks: type(4) totallen(4) body(totallen-12) totallen(4) */
    while (fread(hdr, 1, 8, f) == 8) {
        uint32_t type  = (uint32_t)hdr[0] | hdr[1]<<8 | hdr[2]<<16 | (uint32_t)hdr[3]<<24;
        uint32_t total = rd32(hdr + 4);       /* first SHB: LE default (Windows) */
        if (total < 12) break;

        if (total_bytes) {                     /* live % to stderr (stdout is the CSV) */
            int pct = (int)((uint64_t)ftell(f) * 100 / total_bytes);
            if (pct != last_pct) { fprintf(stderr, "\rProgress: %d%%  ", pct); fflush(stderr); last_pct = pct; }
        }

        fsize = (long)total - 8;              /* body = block minus the 8 bytes read */
        body = (uint8_t *)malloc(fsize);
        if (!body) break;
        if (fread(body, 1, fsize, f) != (size_t)fsize) { free(body); break; }

        if (type == 0x0A0D0D0A) {             /* Section Header: byte-order magic */
            g_swap = !(body[0]==0x4D && body[1]==0x3C && body[2]==0x2B && body[3]==0x1A);
        } else if (type == 0x00000001) {      /* Interface Description: linktype */
            g_linktype = rd16(body);
            /* parse options for if_tsresol (code 9): linktype(2) rsv(2) snap(4) opts */
            { uint32_t o = 8;
              while (o + 4 <= (uint32_t)fsize) {
                  uint16_t code = rd16(body + o), len = rd16(body + o + 2); o += 4;
                  if (code == 0) break;                 /* opt_endofopt */
                  if (code == 9 && len >= 1) {
                      uint8_t v = body[o];
                      if (v & 0x80) { g_tsDenom = (uint64_t)1 << (v & 0x7F); }
                      else { uint8_t e = v; g_tsDenom = 1; while (e--) g_tsDenom *= 10; }
                  }
                  o += (len + 3u) & ~3u;                /* pad to 32-bit */
              }
            }
        } else if (type == 0x00000006) {      /* Enhanced Packet Block */
            /* body: iface(4) tsHi(4) tsLo(4) capLen(4) origLen(4) data... */
            uint32_t capLen = rd32(body + 12);
            g_pktTicks = ((uint64_t)rd32(body + 4) << 32) | rd32(body + 8);
            if (20 + capLen <= (uint32_t)fsize) handle_packet(body + 20, capLen);
        } else if (type == 0x00000003) {      /* Simple Packet Block: origLen(4) data */
            uint32_t origLen = rd32(body);
            if (4 + origLen <= (uint32_t)fsize) handle_packet(body + 4, origLen);
        }
        free(body);
    }
    if (total_bytes) fprintf(stderr, "\r              \r");   /* wipe the progress line */
    fclose(f);
    return 0;
}
