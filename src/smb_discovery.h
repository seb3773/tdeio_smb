#ifndef SMB_DISCOVERY_H
#define SMB_DISCOVERY_H

#include <tqstring.h>
#include <tqvaluelist.h>
#include <tqmap.h>
#include <time.h>

struct SMBDiscoveredHost {
    TQString name;       // Hostname (e.g., "SRV-2019-AD", "SAUV-DS218")
    TQString ip;         // IP address (e.g., "192.168.1.50")
    TQString workgroup;  // Workgroup if available (e.g., "WORKGROUP")
    TQString comment;    // Description or type (e.g., "Printer")
    TQString modelName;  // Printer model name via SNMP (e.g., "Brother DCP-L3550CDW series")
    bool isPrinter;      // true if host is identified as a printer

    SMBDiscoveredHost() : isPrinter(false) {}
};

class SMBDiscovery {
public:
    // Discovers local network hosts using NetBIOS (subnet scan), WSD (multicast UDP 3702), and Avahi (mDNS).
    // Uses a 20-second cache to avoid latency when navigating back and forth in Konqueror.
    static TQValueList<SMBDiscoveredHost> discoverHosts(bool forceRefresh = false, int timeoutMs = 1500);

    // Resolves a display name, model name, or NetBIOS name to the canonical host/IP
    static TQString resolveHostName(const TQString &nameOrModel);

private:
    static void discoverAvahi(TQMap<TQString, SMBDiscoveredHost> &hosts);
    static void discoverNetbiosAndWSD(TQMap<TQString, SMBDiscoveredHost> &hosts, int timeoutMs);
    // Lightweight SNMP query to fetch printer model names
    static void queryPrinterModelsSNMP(TQMap<TQString, SMBDiscoveredHost> &hosts);

    static TQValueList<SMBDiscoveredHost> s_cachedHosts;
    static time_t s_lastDiscoveryTime;
};

#endif // SMB_DISCOVERY_H
