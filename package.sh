#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${DIR}/build"
DIST_DIR="${DIR}/dist"
VERSION="14.1.1-modern1"
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
PKG_NAME="tdeio-smb-modern-discovery"

echo "=========================================="
echo " Packaging: ${PKG_NAME} ${VERSION} (${ARCH})"
echo "=========================================="

# 1. Compilation
export PATH="/opt/trinity/bin:${PATH}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake ..
cmake --build . -j"$(nproc)"

mkdir -p "${DIST_DIR}"

# 2. Build .deb package (using dpkg-divert)
echo "--- Building Debian package (.deb) ---"
PKG_ROOT="${BUILD_DIR}/deb_root"
rm -rf "${PKG_ROOT}"
mkdir -p "${PKG_ROOT}/DEBIAN"
mkdir -p "${PKG_ROOT}/opt/trinity/lib/trinity"
mkdir -p "${PKG_ROOT}/usr/share/doc/${PKG_NAME}"

# Binary and .la
cp "${BUILD_DIR}/tdeio_smb.so" "${PKG_ROOT}/opt/trinity/lib/trinity/tdeio_smb.so"
cat << 'EOF' > "${PKG_ROOT}/opt/trinity/lib/trinity/tdeio_smb.la"
# tdeio_smb.la - a libtool library file
dlname='tdeio_smb.so'
library_names='tdeio_smb.so tdeio_smb.so tdeio_smb.so'
old_library=''
dependency_libs=''
current=0
age=0
revision=0
installed=yes
shouldnotlink=yes
dlopen=''
dlpreopen=''
libdir='/opt/trinity/lib/trinity'
EOF

# Documentation
cat << EOF > "${PKG_ROOT}/usr/share/doc/${PKG_NAME}/README"
tdeio-smb-modern-discovery
==========================
Modern network discovery patch for Trinity Desktop Environment (TDE) kioslave smb:/.
Integrates a native C++ NetBIOS scanner (UDP 137), WS-Discovery (UDP 3702), and Avahi (mDNS)
to restore discovery of Windows machines, Samba shares, NAS, and network printers,
even when legacy SMB1 is disabled on the network.

Safely installed via dpkg-divert: official system files are preserved without risk
of conflict or overwriting during system upgrades (apt upgrade).
EOF

# DEBIAN/control
cat << EOF > "${PKG_ROOT}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: CDEF <cdef@local>
Depends: tdebase-tdeio-smb-trinity, libsmbclient
Description: Modern network discovery (NetBIOS, WSD, mDNS) for Trinity TDE smb:/
 This package enhances the Trinity Desktop Environment SMB kioslave (tdeio_smb)
 to restore automatic discovery of local network machines (smb:/)
 without requiring legacy SMB1.
 Combines native NetBIOS subnet scanning, WS-Discovery, and Avahi (mDNS) in C++.
 Uses dpkg-divert to safely preserve official system files.
EOF

# DEBIAN/preinst
cat << 'EOF' > "${PKG_ROOT}/DEBIAN/preinst"
#!/bin/sh
set -e

if [ "$1" = "install" ] || [ "$1" = "upgrade" ]; then
    dpkg-divert --package tdeio-smb-modern-discovery --add --rename \
        --divert /opt/trinity/lib/trinity/tdeio_smb.so.official \
        /opt/trinity/lib/trinity/tdeio_smb.so
    dpkg-divert --package tdeio-smb-modern-discovery --add --rename \
        --divert /opt/trinity/lib/trinity/tdeio_smb.la.official \
        /opt/trinity/lib/trinity/tdeio_smb.la
fi
exit 0
EOF
chmod 755 "${PKG_ROOT}/DEBIAN/preinst"

# DEBIAN/postinst
cat << 'EOF' > "${PKG_ROOT}/DEBIAN/postinst"
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    pkill -9 -f tdeio_smb 2>/dev/null || true
    if [ -x /opt/trinity/bin/tdebuildsycoca ]; then
        /opt/trinity/bin/tdebuildsycoca >/dev/null 2>&1 || true
    fi
fi
exit 0
EOF
chmod 755 "${PKG_ROOT}/DEBIAN/postinst"

# DEBIAN/prerm
cat << 'EOF' > "${PKG_ROOT}/DEBIAN/prerm"
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
    pkill -9 -f tdeio_smb 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "${PKG_ROOT}/DEBIAN/prerm"

# DEBIAN/postrm
cat << 'EOF' > "${PKG_ROOT}/DEBIAN/postrm"
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    dpkg-divert --package tdeio-smb-modern-discovery --remove --rename \
        --divert /opt/trinity/lib/trinity/tdeio_smb.so.official \
        /opt/trinity/lib/trinity/tdeio_smb.so
    dpkg-divert --package tdeio-smb-modern-discovery --remove --rename \
        --divert /opt/trinity/lib/trinity/tdeio_smb.la.official \
        /opt/trinity/lib/trinity/tdeio_smb.la
    if [ -x /opt/trinity/bin/tdebuildsycoca ]; then
        /opt/trinity/bin/tdebuildsycoca >/dev/null 2>&1 || true
    fi
fi
exit 0
EOF
chmod 755 "${PKG_ROOT}/DEBIAN/postrm"

# Compute md5sums
cd "${PKG_ROOT}"
find opt usr -type f -exec md5sum {} + > DEBIAN/md5sums
cd "${DIR}"

DEB_FILE="${DIST_DIR}/${PKG_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build "${PKG_ROOT}" "${DEB_FILE}"
echo "-> Generated DEB package: ${DEB_FILE}"

# 3. Build standalone user archive (.tar.gz)
echo "--- Building standalone user archive (.tar.gz) ---"
USER_TAR_DIR="${BUILD_DIR}/user_tar"
rm -rf "${USER_TAR_DIR}"
mkdir -p "${USER_TAR_DIR}"

cp "${BUILD_DIR}/tdeio_smb.so" "${USER_TAR_DIR}/tdeio_smb.so"

cat << 'EOF' > "${USER_TAR_DIR}/install.sh"
#!/bin/bash
set -e

USER_LIB="${HOME}/.trinity/lib/trinity"
echo "=== Installing into ${USER_LIB} (rootless) ==="
mkdir -p "${USER_LIB}"
cp -v "$(dirname "$0")/tdeio_smb.so" "${USER_LIB}/tdeio_smb.so"

cat << LAEOF > "${USER_LIB}/tdeio_smb.la"
# tdeio_smb.la - a libtool library file
dlname='tdeio_smb.so'
library_names='tdeio_smb.so tdeio_smb.so tdeio_smb.so'
old_library=''
dependency_libs=''
current=0
age=0
revision=0
installed=yes
shouldnotlink=yes
dlopen=''
dlpreopen=''
libdir='${USER_LIB}'
LAEOF

echo "Refreshing TDE caches..."
pkill -9 -f tdeio_smb 2>/dev/null || true
if [ -x /opt/trinity/bin/tdebuildsycoca ]; then
    /opt/trinity/bin/tdebuildsycoca >/dev/null 2>&1 || true
fi
echo "Installation successful!"
EOF
chmod +x "${USER_TAR_DIR}/install.sh"

cat << 'EOF' > "${USER_TAR_DIR}/uninstall.sh"
#!/bin/bash
set -e

USER_LIB="${HOME}/.trinity/lib/trinity"
echo "=== Uninstalling user module ==="
rm -f "${USER_LIB}/tdeio_smb.so" "${USER_LIB}/tdeio_smb.la"

echo "Refreshing TDE caches..."
pkill -9 -f tdeio_smb 2>/dev/null || true
if [ -x /opt/trinity/bin/tdebuildsycoca ]; then
    /opt/trinity/bin/tdebuildsycoca >/dev/null 2>&1 || true
fi
echo "Uninstallation successful (restored default tdeio_smb)."
EOF
chmod +x "${USER_TAR_DIR}/uninstall.sh"

cat << EOF > "${USER_TAR_DIR}/README.txt"
Rootless install for Trinity Desktop :
--------------------------------------
1.  './install.sh' to enable modern discovery smb:/
2.  './uninstall.sh' to disable and back to legacy
EOF

TAR_FILE="${DIST_DIR}/${PKG_NAME}_${VERSION}_user_${ARCH}.tar.gz"
cd "${USER_TAR_DIR}"
tar -czf "${TAR_FILE}" *
cd "${DIR}"
echo "-> User archive created: ${TAR_FILE}"

echo "=========================================="
echo " Packaging ok (in dist/):"
ls -lh "${DIST_DIR}"
echo "=========================================="
