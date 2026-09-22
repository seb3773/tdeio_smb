cmake_minimum_required(VERSION 3.10)
project(tdeio_smb CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Aggressive compilation flags (inspired by taskmgr) ---
# Disable with: cmake -DAGGRESSIVE_FLAGS=OFF ..
option(AGGRESSIVE_FLAGS "Enable aggressive -O2/LTO compile flags for size reduction" ON)

if(AGGRESSIVE_FLAGS)
    set(_C_BASE "-O2 -flto=auto -fstrict-aliasing -ffunction-sections -fdata-sections -fno-ident -fno-plt -fomit-frame-pointer -fno-stack-protector -fno-math-errno -fvisibility=hidden -fmerge-all-constants -fno-asynchronous-unwind-tables -DNDEBUG")
    set(_CXX_EXTRA "-fno-threadsafe-statics -fno-exceptions -fmerge-all-constants")
    set(CMAKE_CXX_FLAGS "${_C_BASE} ${_CXX_EXTRA}")
    # Linker: gc-sections eliminates dead code, -s strips debug symbols, --as-needed strips unused deps
    set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-O1 -Wl,--gc-sections -Wl,--as-needed -Wl,--build-id=none -Wl,-z,norelro -flto=auto -s")
    # Override CMake default flags to prevent conflicts
    set(CMAKE_CXX_FLAGS_DEBUG "")
    set(CMAKE_CXX_FLAGS_RELEASE "")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "")
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    endif()
    message(STATUS "Aggressive optimization flags ENABLED (LTO + strip + gc-sections)")
endif()
# Ensure tde-config is located if not defined
if(NOT DEFINED KDECONFIG_EXECUTABLE)
  find_program(KDECONFIG_EXECUTABLE
    NAMES tde-config
    HINTS /opt/trinity/bin
  )
endif()

if(NOT DEFINED TMOC_EXECUTABLE)
  find_program(TMOC_EXECUTABLE
    NAMES tqmoc tmoc moc-tqt
    HINTS /usr/bin /opt/trinity/bin
  )
endif()

# Configure PKG_CONFIG_PATH to find tdelibs.pc and tqt
set(ENV{PKG_CONFIG_PATH} "/opt/trinity/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

find_package(PkgConfig REQUIRED)
pkg_check_modules(TQT REQUIRED tqt)
add_definitions(${TQT_CFLAGS_OTHER})

include(TDEMacros)
find_package(TDE REQUIRED)

# Check for libsmbclient headers (system or fallback third_party)
find_path(SMBCLIENT_INCLUDE_DIR
  NAMES libsmbclient.h
  PATHS
    /usr/include/samba-4.0
    /usr/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/usr/include/samba-4.0
)

message(STATUS "SMBClient include dir: ${SMBCLIENT_INCLUDE_DIR}")

# Inclusions
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}
  /opt/trinity/include
  /opt/trinity/include/tde
  ${TDE_INCLUDE_DIR}
  ${TDE_INCLUDE_DIR}/tde
  ${TQT_INCLUDE_DIRS}
  /usr/include/tqt
  /usr/include/tqt3
  ${SMBCLIENT_INCLUDE_DIR}
)

link_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/usr/lib/x86_64-linux-gnu
  /opt/trinity/lib
  ${TQT_LIBRARY_DIRS}
)

set(tdeio_smb_SRCS
  src/tdeio_smb.cpp
  src/tdeio_smb_auth.cpp
  src/tdeio_smb_browse.cpp
  src/tdeio_smb_config.cpp
  src/tdeio_smb_dir.cpp
  src/tdeio_smb_file.cpp
  src/tdeio_smb_internal.cpp
  src/tdeio_smb_mount.cpp
  src/smb_discovery.cpp
)

tde_add_kpart(tdeio_smb AUTOMOC
  SOURCES ${tdeio_smb_SRCS}
  LINK
    tdeio-shared
    tdecore-shared
    smbclient
    ${TQT_LIBRARIES}
  DESTINATION ${PLUGIN_INSTALL_DIR}
)
