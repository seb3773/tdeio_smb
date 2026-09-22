#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${DIR}/build"
USER_LIB="${HOME}/.trinity/lib/trinity"

echo "=== compiling tdeio_smb ==="
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake ..
cmake --build . -j"$(nproc)"

echo "=== deploy in ${USER_LIB} ==="
mkdir -p "${USER_LIB}"
cp -v "${BUILD_DIR}/tdeio_smb.so" "${USER_LIB}/tdeio_smb.so"

cat << EOF > "${USER_LIB}/tdeio_smb.la"
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
EOF

echo "=== Refreshing TDE caches ==="
pkill -9 -f "tdeio_smb" 2>/dev/null || true
if command -v /opt/trinity/bin/tdebuildsycoca >/dev/null 2>&1; then
    /opt/trinity/bin/tdebuildsycoca >/dev/null 2>&1 || true
fi
if command -v /opt/trinity/bin/dcop >/dev/null 2>&1; then
    /opt/trinity/bin/dcop tdelauncher tdelauncher reparseConfiguration >/dev/null 2>&1 || true
fi

echo "=== Deploy finished. ==="
