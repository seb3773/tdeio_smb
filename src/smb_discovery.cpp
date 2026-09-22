#include "smb_discovery.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>

#include <tqstringlist.h>
#include <tqregexp.h>
#include <kdebug.h>

#define TDEIO_SMB 7106

TQValueList<SMBDiscoveredHost> SMBDiscovery::s_cachedHosts;
time_t SMBDiscovery::s_lastDiscoveryTime = 0;

static const unsigned char NBT_NODE_STATUS_REQ[50] = {
    0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
    0x00, 0x01
};

TQValueList<SMBDiscoveredHost> SMBDiscovery::discoverHosts(bool forceRefresh, int timeoutMs)
{
    time_t now = time(NULL);
    if (!forceRefresh && s_lastDiscoveryTime > 0 && (now - s_lastDiscoveryTime < 20) && !s_cachedHosts.isEmpty()) {
        kdDebug(TDEIO_SMB) << "SMBDiscovery: returning cached host list (" << s_cachedHosts.count() << " hosts)" << endl;
        return s_cachedHosts;
    }

    kdDebug(TDEIO_SMB) << "SMBDiscovery: starting host discovery (NetBIOS + WSD + Avahi)..." << endl;
    TQMap<TQString, SMBDiscoveredHost> hostMap;

    // 1. Fast Avahi discovery (mDNS _smb._tcp)
    discoverAvahi(hostMap);

    // 2. Joint NetBIOS (subnet scan) + WS-Discovery (multicast UDP 3702) discovery
    discoverNetbiosAndWSD(hostMap, timeoutMs);

    // 3. SNMP queries for model names of detected printers
    queryPrinterModelsSNMP(hostMap);

    // Sort and convert map to ordered list
    TQValueList<SMBDiscoveredHost> result;
    for (TQMap<TQString, SMBDiscoveredHost>::Iterator it = hostMap.begin(); it != hostMap.end(); ++it) {
        result.append(it.data());
    }

    s_cachedHosts = result;
    s_lastDiscoveryTime = now;
    kdDebug(TDEIO_SMB) << "SMBDiscovery: completed, found " << result.count() << " hosts" << endl;
    return result;
}

TQString SMBDiscovery::resolveHostName(const TQString &nameOrModel)
{
    if (nameOrModel.isEmpty()) return nameOrModel;

    // If string is in format "Model (NETBIOS_NAME)", extract the name
    int parenOpen = nameOrModel.findRev('(');
    int parenClose = nameOrModel.findRev(')');
    if (parenOpen != -1 && parenClose > parenOpen + 1) {
        TQString inside = nameOrModel.mid(parenOpen + 1, parenClose - parenOpen - 1).stripWhiteSpace();
        if (!inside.isEmpty()) {
            return inside;
        }
    }

    TQString upper = nameOrModel.upper().stripWhiteSpace();

    for (TQValueList<SMBDiscoveredHost>::ConstIterator it = s_cachedHosts.begin(); it != s_cachedHosts.end(); ++it) {
        if ((*it).name.upper() == upper) {
            return (*it).name;
        }
        if (!(*it).modelName.isEmpty() && (*it).modelName.upper() == upper) {
            return (*it).name;
        }
    }

    return nameOrModel;
}

void SMBDiscovery::discoverAvahi(TQMap<TQString, SMBDiscoveredHost> &hosts)
{
    FILE *fp = popen("/usr/bin/avahi-browse -t -r -p _smb._tcp 2>/dev/null", "r");
    if (!fp) {
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] != '=') {
            continue;
        }

        TQString qline = TQString::fromUtf8(line).stripWhiteSpace();
        TQStringList parts = TQStringList::split(';', qline, true);
        if (parts.count() >= 8) {
            TQString srvName = parts[3].stripWhiteSpace();
            TQString srvIp = parts[7].stripWhiteSpace();

            if (!srvName.isEmpty() && !srvIp.isEmpty()) {
                TQString upperName = srvName.upper();
                if (srvIp == "127.0.0.1" && hosts.contains(upperName)) {
                    continue;
                }

                if (!hosts.contains(upperName)) {
                    SMBDiscoveredHost host;
                    host.name = upperName;
                    host.ip = srvIp;
                    host.comment = parts.count() > 4 ? parts[4] : TQString("mDNS");
                    hosts.insert(upperName, host);
                    kdDebug(TDEIO_SMB) << "SMBDiscovery [Avahi]: found " << upperName << " (" << srvIp << ")" << endl;
                }
            }
        }
    }
    pclose(fp);
}

void SMBDiscovery::discoverNetbiosAndWSD(TQMap<TQString, SMBDiscoveredHost> &hosts, int timeoutMs)
{
    // --- WSD Socket Initialization ---
    int wsd_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (wsd_sock >= 0) {
        int broadcast = 1;
        setsockopt(wsd_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(3702);
        dest.sin_addr.s_addr = inet_addr("239.255.255.250");

        char uuidStr[64];
        srand(time(NULL) ^ getpid());
        snprintf(uuidStr, sizeof(uuidStr), "%08x-%04x-4%03x-%04x-%012lx",
                 rand(), rand() & 0xffff, rand() & 0xfff, (rand() & 0x3fff) | 0x8000,
                 ((unsigned long)rand() << 32) | rand());

        TQString probeMsg = TQString(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
            "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
            "xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">"
            "<soap:Header>"
            "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
            "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
            "<wsa:MessageID>urn:uuid:%1</wsa:MessageID>"
            "</soap:Header>"
            "<soap:Body><wsd:Probe/></soap:Body>"
            "</soap:Envelope>").arg(uuidStr);

        TQCString probeUtf8 = probeMsg.utf8();
        sendto(wsd_sock, probeUtf8.data(), probeUtf8.length(), 0, (struct sockaddr*)&dest, sizeof(dest));
    }

    // --- NetBIOS Socket Initialization (UDP port 137) ---
    int nbt_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (nbt_sock >= 0) {
        int bcast = 1;
        setsockopt(nbt_sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_port = htons(0);
        bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        bind(nbt_sock, (struct sockaddr*)&bindAddr, sizeof(bindAddr));

        // Detect active local subnets via getifaddrs
        struct ifaddrs *ifaddr = NULL;
        if (getifaddrs(&ifaddr) == 0) {
            for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
                if (ifa->ifa_flags & IFF_LOOPBACK) continue;
                if (!(ifa->ifa_flags & IFF_UP)) continue;

                // Ignore virtualization and container interfaces
                if (strncmp(ifa->ifa_name, "docker", 6) == 0 ||
                    strncmp(ifa->ifa_name, "virbr", 5) == 0 ||
                    strncmp(ifa->ifa_name, "veth", 4) == 0) {
                    continue;
                }

                struct sockaddr_in *ip = (struct sockaddr_in *)ifa->ifa_addr;
                struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;
                if (!netmask) continue;

                uint32_t ip_val = ntohl(ip->sin_addr.s_addr);
                uint32_t mask_val = ntohl(netmask->sin_addr.s_addr);
                uint32_t net_val = ip_val & mask_val;
                uint32_t bcast_val = net_val | (~mask_val);
                uint32_t count = bcast_val - net_val;

                // Limit direct scan to subnets <= /22 (1024 hosts) to keep discovery lightweight
                if (count > 1024) continue;

                struct sockaddr_in target;
                memset(&target, 0, sizeof(target));
                target.sin_family = AF_INET;
                target.sin_port = htons(137);

                for (uint32_t curr = net_val + 1; curr < bcast_val; curr++) {
                    target.sin_addr.s_addr = htonl(curr);
                    sendto(nbt_sock, NBT_NODE_STATUS_REQ, sizeof(NBT_NODE_STATUS_REQ), 0,
                           (struct sockaddr*)&target, sizeof(target));
                }
                // Also send to subnet broadcast IP
                target.sin_addr.s_addr = htonl(bcast_val);
                sendto(nbt_sock, NBT_NODE_STATUS_REQ, sizeof(NBT_NODE_STATUS_REQ), 0,
                       (struct sockaddr*)&target, sizeof(target));
            }
            freeifaddrs(ifaddr);
        }
    }

    // --- Combined WSD + NetBIOS reception loop via poll ---
    struct pollfd pfds[2];
    int nfds = 0;
    int wsd_idx = -1;
    int nbt_idx = -1;

    if (wsd_sock >= 0) {
        wsd_idx = nfds;
        pfds[nfds].fd = wsd_sock;
        pfds[nfds].events = POLLIN;
        nfds++;
    }
    if (nbt_sock >= 0) {
        nbt_idx = nfds;
        pfds[nfds].fd = nbt_sock;
        pfds[nfds].events = POLLIN;
        nfds++;
    }

    struct timeval start, current;
    gettimeofday(&start, NULL);

    char wsd_buf[65536];
    unsigned char nbt_buf[4096];

    while (nfds > 0) {
        gettimeofday(&current, NULL);
        long elapsedMs = (current.tv_sec - start.tv_sec) * 1000 + (current.tv_usec - start.tv_usec) / 1000;
        int remainingMs = timeoutMs - (int)elapsedMs;
        if (remainingMs <= 0) {
            break;
        }

        int ret = poll(pfds, nfds, remainingMs > 100 ? 100 : remainingMs);
        if (ret <= 0) {
            continue;
        }

        // 1. WSD reception
        if (wsd_idx >= 0 && (pfds[wsd_idx].revents & POLLIN)) {
            struct sockaddr_in srcAddr;
            socklen_t addrLen = sizeof(srcAddr);
            ssize_t n = recvfrom(wsd_sock, wsd_buf, sizeof(wsd_buf) - 1, 0, (struct sockaddr*)&srcAddr, &addrLen);
            if (n > 0) {
                wsd_buf[n] = '\0';
                TQString reply = TQString::fromUtf8(wsd_buf);
                char srcIpStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &srcAddr.sin_addr, srcIpStr, sizeof(srcIpStr));
                TQString ip(srcIpStr);

                bool isPrinter = reply.contains("PrintDeviceType");

                TQRegExp rx("http://([^:/]+):[0-9]+/");
                if (rx.search(reply) != -1) {
                    TQString hostCandidate = rx.cap(1).stripWhiteSpace();
                    TQRegExp ipRx("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$");
                    if (!ipRx.exactMatch(hostCandidate)) {
                        TQString upperHost = hostCandidate.upper();
                        if (!hosts.contains(upperHost)) {
                            SMBDiscoveredHost h;
                            h.name = upperHost;
                            h.ip = ip;
                            h.isPrinter = isPrinter;
                            h.comment = isPrinter ? TQString("Printer") : TQString("WSD");
                            hosts.insert(upperHost, h);
                            kdDebug(TDEIO_SMB) << "SMBDiscovery [WSD]: found " << upperHost << " (" << ip << ")" << (isPrinter ? " [Printer]" : "") << endl;
                        }
                    }
                }
            }
        }

        // 2. NetBIOS Node Status reception
        if (nbt_idx >= 0 && (pfds[nbt_idx].revents & POLLIN)) {
            struct sockaddr_in srcAddr;
            socklen_t addrLen = sizeof(srcAddr);
            ssize_t n = recvfrom(nbt_sock, nbt_buf, sizeof(nbt_buf), 0, (struct sockaddr*)&srcAddr, &addrLen);
            if (n > 56) {
                uint8_t num_names = nbt_buf[56];
                size_t offset = 57;
                TQString srvName, wgName;

                for (uint8_t i = 0; i < num_names && offset + 18 <= (size_t)n; i++) {
                    char raw[16];
                    memcpy(raw, nbt_buf + offset, 15);
                    raw[15] = '\0';
                    int k = 14;
                    while (k >= 0 && (raw[k] == ' ' || raw[k] == '\0')) {
                        raw[k] = '\0';
                        k--;
                    }
                    uint8_t svc = nbt_buf[offset + 15];
                    uint16_t flags = (nbt_buf[offset + 16] << 8) | nbt_buf[offset + 17];
                    bool is_group = (flags & 0x8000) != 0;

                    TQString nameStr = TQString::fromLatin1(raw).stripWhiteSpace();
                    if (!is_group) {
                        if (svc == 0x20 || (srvName.isEmpty() && svc == 0x00)) {
                            srvName = nameStr;
                        }
                    } else {
                        if (svc == 0x00 && wgName.isEmpty()) {
                            wgName = nameStr;
                        }
                    }
                    offset += 18;
                }

                if (!srvName.isEmpty()) {
                    TQString upperHost = srvName.upper();
                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &srcAddr.sin_addr, ipStr, sizeof(ipStr));
                    TQString ip(ipStr);

                    if (!hosts.contains(upperHost)) {
                        SMBDiscoveredHost h;
                        h.name = upperHost;
                        h.ip = ip;
                        h.workgroup = wgName;
                        if (upperHost.startsWith("BRN") || upperHost.startsWith("BRW") ||
                            upperHost.startsWith("KM") || upperHost.startsWith("CANON") ||
                            upperHost.startsWith("NPI") || upperHost.startsWith("HP") ||
                            upperHost.startsWith("ET") || upperHost.startsWith("EPSON") ||
                            upperHost.startsWith("RICOH") || upperHost.startsWith("XEROX") ||
                            upperHost.startsWith("LEXMARK") || upperHost.startsWith("SHARP") ||
                            upperHost.startsWith("OKI") || upperHost.startsWith("KONICA") ||
                            upperHost.startsWith("MINOLTA") || upperHost.startsWith("KYOCERA")) {
                            h.isPrinter = true;
                            h.comment = "Printer";
                        }
                        hosts.insert(upperHost, h);
                        kdDebug(TDEIO_SMB) << "SMBDiscovery [NetBIOS]: found " << upperHost << " [WG: " << wgName << "] (" << ip << ")" << endl;
                    } else {
                        if (!wgName.isEmpty() && hosts[upperHost].workgroup.isEmpty()) {
                            hosts[upperHost].workgroup = wgName;
                        }
                    }
                }
            }
        }
    }

    if (wsd_sock >= 0) close(wsd_sock);
    if (nbt_sock >= 0) close(nbt_sock);
}

// ---------------------------------------------------------------------------
// Lightweight SNMP query (SNMPv1 GETNEXT) to retrieve printer model names.
// Uses non-blocking UDP sockets + poll() to query all printers in parallel (~300ms).
// OID: hrDeviceDescr = 1.3.6.1.2.1.25.3.2.1.3
// Fallback: sysDescr  = 1.3.6.1.2.1.1.1
// ---------------------------------------------------------------------------

// Static SNMPv1 GETNEXT request for hrDeviceDescr (1.3.6.1.2.1.25.3.2.1.3)
static const unsigned char SNMP_GETNEXT_HRDEVICE[42] = {
    0x30, 0x28,                         // SEQUENCE (40 bytes)
    0x02, 0x01, 0x00,                   // INTEGER version 0 (SNMPv1)
    0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // STRING "public"
    0xa1, 0x1b,                         // GetNextRequest (27 bytes)
    0x02, 0x01, 0x01,                   // request-id 1
    0x02, 0x01, 0x00,                   // error-status 0
    0x02, 0x01, 0x00,                   // error-index 0
    0x30, 0x10,                         // VarBindList (16 bytes)
    0x30, 0x0e,                         // VarBind (14 bytes)
    0x06, 0x0a,                         // OID (10 bytes)
    0x2b, 0x06, 0x01, 0x02, 0x01, 0x19, 0x03, 0x02, 0x01, 0x03, // 1.3.6.1.2.1.25.3.2.1.3
    0x05, 0x00                          // NULL
};

// Static SNMPv1 GETNEXT request for sysDescr (1.3.6.1.2.1.1.1)
static const unsigned char SNMP_GETNEXT_SYSDESCR[40] = {
    0x30, 0x26,                         // SEQUENCE (38 bytes)
    0x02, 0x01, 0x00,                   // INTEGER version 0 (SNMPv1)
    0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // STRING "public"
    0xa1, 0x19,                         // GetNextRequest (25 bytes)
    0x02, 0x01, 0x01,                   // request-id 1
    0x02, 0x01, 0x00,                   // error-status 0
    0x02, 0x01, 0x00,                   // error-index 0
    0x30, 0x0e,                         // VarBindList (14 bytes)
    0x30, 0x0c,                         // VarBind (12 bytes)
    0x06, 0x08,                         // OID (8 bytes)
    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x01, // 1.3.6.1.2.1.1.1
    0x05, 0x00                          // NULL
};

// Extract string value from an SNMP response
static TQString parseSNMPStringResponse(const unsigned char *data, int len) {
    // Look for last 0x04 tag (Octet String) in response
    for (int i = len - 3; i > 10; i--) {
        if (data[i] == 0x04 && data[i+1] < 128 && (i + 2 + data[i+1]) <= len) {
            int strLen = data[i+1];
            if (strLen >= 2 && strLen < 200) {
                return TQString::fromLatin1((const char*)(data + i + 2), strLen).stripWhiteSpace();
            }
        }
    }
    return TQString::null;
}

void SMBDiscovery::queryPrinterModelsSNMP(TQMap<TQString, SMBDiscoveredHost> &hosts) {
    // Collect IPs of detected printers
    struct PrinterQuery {
        TQString ip;
        TQString key;
        bool gotModel;
    };

    TQValueList<PrinterQuery> queries;
    for (TQMap<TQString, SMBDiscoveredHost>::Iterator it = hosts.begin(); it != hosts.end(); ++it) {
        if (it.data().isPrinter && !it.data().ip.isEmpty()) {
            PrinterQuery q;
            q.ip = it.data().ip;
            q.key = it.key();
            q.gotModel = false;
            queries.append(q);
        }
    }

    if (queries.isEmpty()) return;

    kdDebug(TDEIO_SMB) << "SMBDiscovery [SNMP]: querying " << queries.count() << " printers for model names" << endl;

    // Single UDP socket for all queries
    int snmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (snmp_sock < 0) return;

    // Send hrDeviceDescr GETNEXT requests to all printers
    for (TQValueList<PrinterQuery>::Iterator it = queries.begin(); it != queries.end(); ++it) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(161);
        inet_pton(AF_INET, (*it).ip.latin1(), &dest.sin_addr);
        sendto(snmp_sock, SNMP_GETNEXT_HRDEVICE, sizeof(SNMP_GETNEXT_HRDEVICE), 0,
               (struct sockaddr*)&dest, sizeof(dest));
    }

    // Receive responses with poll() (timeout 400ms)
    struct pollfd pfd;
    pfd.fd = snmp_sock;
    pfd.events = POLLIN;

    struct timeval start, now;
    gettimeofday(&start, NULL);
    unsigned char resp[4096];
    int remaining = (int)queries.count();

    while (remaining > 0) {
        gettimeofday(&now, NULL);
        long elapsedMs = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int timeLeft = 400 - (int)elapsedMs;
        if (timeLeft <= 0) break;

        int ret = poll(&pfd, 1, timeLeft > 50 ? 50 : timeLeft);
        if (ret <= 0) continue;

        struct sockaddr_in srcAddr;
        socklen_t addrLen = sizeof(srcAddr);
        ssize_t n = recvfrom(snmp_sock, resp, sizeof(resp), 0, (struct sockaddr*)&srcAddr, &addrLen);
        if (n <= 0) continue;

        char srcIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &srcAddr.sin_addr, srcIp, sizeof(srcIp));
        TQString ip(srcIp);

        TQString model = parseSNMPStringResponse(resp, (int)n);
        if (!model.isEmpty()) {
            // Match with corresponding printer
            for (TQValueList<PrinterQuery>::Iterator it = queries.begin(); it != queries.end(); ++it) {
                if ((*it).ip == ip && !(*it).gotModel) {
                    (*it).gotModel = true;
                    remaining--;
                    if (hosts.contains((*it).key)) {
                        hosts[(*it).key].modelName = model;
                        hosts[(*it).key].comment = model;
                        kdDebug(TDEIO_SMB) << "SMBDiscovery [SNMP]: " << (*it).key << " -> " << model << endl;
                    }
                    break;
                }
            }
        }
    }

    // Phase 2: Send sysDescr GETNEXT for printers that did not reply to hrDeviceDescr
    bool needFallback = false;
    for (TQValueList<PrinterQuery>::Iterator it = queries.begin(); it != queries.end(); ++it) {
        if (!(*it).gotModel) {
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(161);
            inet_pton(AF_INET, (*it).ip.latin1(), &dest.sin_addr);
            sendto(snmp_sock, SNMP_GETNEXT_SYSDESCR, sizeof(SNMP_GETNEXT_SYSDESCR), 0,
                   (struct sockaddr*)&dest, sizeof(dest));
            needFallback = true;
        }
    }

    if (needFallback) {
        gettimeofday(&start, NULL);
        while (true) {
            gettimeofday(&now, NULL);
            long elapsedMs = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
            int timeLeft = 300 - (int)elapsedMs;
            if (timeLeft <= 0) break;

            int ret = poll(&pfd, 1, timeLeft > 50 ? 50 : timeLeft);
            if (ret <= 0) continue;

            struct sockaddr_in srcAddr;
            socklen_t addrLen = sizeof(srcAddr);
            ssize_t n = recvfrom(snmp_sock, resp, sizeof(resp), 0, (struct sockaddr*)&srcAddr, &addrLen);
            if (n <= 0) continue;

            char srcIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &srcAddr.sin_addr, srcIp, sizeof(srcIp));
            TQString ip(srcIp);

            TQString desc = parseSNMPStringResponse(resp, (int)n);
            if (!desc.isEmpty()) {
                for (TQValueList<PrinterQuery>::Iterator it = queries.begin(); it != queries.end(); ++it) {
                    if ((*it).ip == ip && !(*it).gotModel) {
                        (*it).gotModel = true;
                        if (hosts.contains((*it).key)) {
                            hosts[(*it).key].modelName = desc;
                            hosts[(*it).key].comment = desc;
                            kdDebug(TDEIO_SMB) << "SMBDiscovery [SNMP/sysDescr]: " << (*it).key << " -> " << desc << endl;
                        }
                        break;
                    }
                }
            }
        }
    }

    close(snmp_sock);
}
