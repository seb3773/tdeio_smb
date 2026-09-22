# tdeio_smb

**Modern Network Discovery (NetBIOS, WS-Discovery, Avahi/mDNS & SNMP) for Trinity Desktop Environment (TDE)**

`tdeio_smb` is an enhanced SMB/CIFS KIO slave (`smb:/`) for the [Trinity Desktop Environment](https://www.trinitydesktop.org/) (TDE). It brings modern local network discovery to Konqueror and TDE file dialogs without requiring legacy, insecure SMBv1 / NetBIOS master browser services.

---

## The Problem

The original TDE `tdeio_smb` kioslave relied exclusively on legacy SMBv1 NetBIOS broadcast announcements (`smbclient -L` / workgroup master browsers).

In modern network environments:
* **SMBv1 is disabled by default** on Windows 10, Windows 11, Windows Server (2016–2025), and modern Samba distributions for security reasons.
* Network workgroup browsing via master browsers often returns empty results or fails entirely.
* Browsing `smb:/` in Konqueror showed no computers or only a few legacy machines.

## The Solution

This project extends `tdeio_smb` with a fast, lightweight, native C++ multi-protocol discovery engine:

1. **Native NetBIOS Subnet Scanner (UDP 137)**: Sends Node Status queries across the local subnet (`/24`, up to `/22`) to discover Windows, Linux Samba, and NAS devices, resolving their NetBIOS machine names and active workgroups.
2. **WS-Discovery / WSD (UDP 3702)**: Multicast SOAP probe (`urn:schemas-xmlsoap-org:ws:2005:04:discovery`) detecting modern Windows machines and WSD-enabled devices.
3. **Avahi / mDNS (`_smb._tcp`)**: Discovers Linux Samba servers, NAS appliances, and macOS computers publishing SMB services.
4. **SNMP Printer Model Identification (UDP 161)**: Automatically identifies network printers and queries `hrDeviceDescr` (`1.3.6.1.2.1.25.3.2.1.3.1`) and `sysDescr` (`1.3.6.1.2.1.1.1.0`) in parallel non-blocking UDP sockets, displaying clean printer icons and their exact commercial model names (e.g. *Brother DCP-L3550CDW*, *HP LaserJet*, *Canon*, *Epson*, etc.).
5. **Intelligent Caching**: Keeps discovered hosts in memory for 20 seconds to make navigating back and forth in Konqueror instantaneous.
6. **Optimized Footprint**: Built with Link-Time Optimization (LTO), dead code elimination (`-Wl,--gc-sections`), and hidden visibility, resulting in a compact shared library (~97 KB).

---

## Requirements

### Build Dependencies

* Debian / Ubuntu / Devuan with Trinity Desktop Environment (TDE R14.x)
* `cmake` (>= 3.10)
* `build-essential` (`g++`, `gcc`, `make`)
* `tdelibs14-trinity-dev`
* `libsmbclient-dev`
* `tqt3-dev-tools`
* `pkg-config`

### Runtime Dependencies

* `libsmbclient` (Samba 4.x client library)
* `avahi-utils` (optional, provides `avahi-browse` for mDNS discovery)

---

## Building

Clone the repository and build:

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

To build and package both the `.deb` package and the standalone user archive in one step:

```bash
./package.sh
```

Output packages will be generated in `dist/`:
* `dist/tdeio-smb-modern-discovery_<version>_<arch>.deb`
* `dist/tdeio-smb-modern-discovery_<version>_user_<arch>.tar.gz`

---

## Installation

### Method 1: System-wide Debian Package (Recommended)

The `.deb` package uses Debian's `dpkg-divert` mechanism. This ensures the official TDE `tdeio_smb.so` and `tdeio_smb.la` files are safely diverted (`.official`), preventing conflicts and ensuring system updates (`apt upgrade`) do not break your installation.

```bash
sudo dpkg -i dist/tdeio-smb-modern-discovery_*.deb
```

To uninstall and restore the original TDE kioslave:

```bash
sudo dpkg -r tdeio-smb-modern-discovery
```

### Method 2: Rootless / Per-User Installation

If you don't have `root` access or want to test without modifying system files, use the user archive:

```bash
tar -xzf dist/tdeio-smb-modern-discovery_*_user_*.tar.gz
cd <extracted_folder>
./install.sh
```

This installs the module to `~/.trinity/lib/trinity/`, taking precedence over `/opt/trinity/lib/trinity/`.

To uninstall:

```bash
./uninstall.sh
```

### Method 3: Direct Deployment (Development)

For quick development iteration, run:

```bash
./deploy.sh
```

---

## How It Works

```
Konqueror / TDE App
       │
       ▼
   smb:/ URL
       │
       ▼
┌────────────────────────────────────────────────────────┐
│                   tdeio_smb                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │               SMBDiscovery                       │  │
│  │  ├─ Avahi mDNS (_smb._tcp)                       │  │
│  │  ├─ WS-Discovery Probe (UDP 3702)                │  │
│  │  ├─ NetBIOS Node Status Scanner (UDP 137)        │  │
│  │  └─ SNMP Parallel Model Query (UDP 161)          │  │
│  └──────────────────────────────────────────────────┘  │
│                          │                             │
│                          ▼                             │
│               Populate KIO UDS Entries                 │
│         (PC icons, Printer icons + Model names)        │
└────────────────────────────────────────────────────────┘
       │
       ▼
Clicking a host (e.g. smb://SERVER/ or smb://PRINTER/)
       │
       ▼
Standard libsmbclient (SMB2 / SMB3 negotiation)
Lists shares, prompts for credentials if necessary
```

---

## License

This project is licensed under the **GNU General Public License (GPL) version 2.1 or later**, following the original Trinity Desktop Environment / KDE KIO slave licensing.
