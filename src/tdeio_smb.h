/////////////////////////////////////////////////////////////////////////////
//
// Project:     SMB tdeioslave for KDE2
//
// File:        tdeio_smb.h
//
// Abstract:    The main tdeio slave class declaration.  For convenience,
//              in concurrent devlopment, the implementation for this class
//              is separated into several .cpp files -- the file containing
//              the implementation should be noted in the comments for each
//              member function.
//
// Author(s):   Matthew Peterson <mpeterson@caldera.com>
//
//---------------------------------------------------------------------------
//
// Copyright (c) 2000  Caldera Systems, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2.1 of the License, or
// (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Lesser General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program; see the file COPYING.  If not, please obtain
//     a copy from http://www.gnu.org/copyleft/gpl.html
//
/////////////////////////////////////////////////////////////////////////////


#ifndef TDEIO_SMB_H_INCLUDED
#define TDEIO_SMB_H_INCLUDED

//-------------
// QT includes
//-------------
#include <tqstring.h>
#include <tqptrlist.h>
#include <tqstringlist.h>
#include <tqtextstream.h>
#include <tqstrlist.h>

//--------------
// KDE includes
//--------------
#include <kdebug.h>
#include <kinstance.h>
#include <tdeio/global.h>
#include <tdeio/slavebase.h>
#include <kurl.h>
#include <tdelocale.h>

//-----------------------------
// Standard C library includes
//-----------------------------
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <tqobject.h>

//-------------------------------
// Samba client library includes
//-------------------------------
extern "C"
{
#include <libsmbclient.h>
}

//---------------------------
// tdeio_smb internal includes
//---------------------------
#include "tdeio_smb_internal.h"

#define MAX_XFER_BUF_SIZE           16348
#define TDEIO_SMB                     7106

using namespace TDEIO;
class TDEProcess;

//===========================================================================


class SMBSlave : public TQObject, public TDEIO::SlaveBase
{
    TQ_OBJECT

private:
    //---------------------------------------------------------------------
    // please make sure your private data does not duplicate existing data
    //---------------------------------------------------------------------
    bool     m_initialized_smbc;

    /**
     * From Controlcenter
     */
    TQString  m_default_user;
//    TQString  m_default_workgroup; //currently unused, Alex <neundorf@kde.org>
    TQString  m_default_password;
    TQString  m_default_encoding;

    /**
     * we store the current url, it's needed for
     * callback authorisation method
     */
    SMBUrl   m_current_url;

    /**
     * From Controlcenter, show SHARE$ or not
     */
//    bool m_showHiddenShares;     //currently unused, Alex <neundorf@kde.org>

    /**
     * libsmbclient need global variables to store in,
     * else it crashes on exit next method after use cache_stat,
     * looks like gcc (C/C++) failure
     */
    struct stat st;
protected:
    //---------------------------------------------
    // Authentication functions (tdeio_smb_auth.cpp)
    //---------------------------------------------
    // (please prefix functions with auth)


    /**
     * Description :   Initilizes the libsmbclient
     * Return :        true on success false with errno set on error
     */
    bool auth_initialize_smbc();

    bool checkPassword(SMBUrl &url);


    //---------------------------------------------
    // Cache functions (tdeio_smb_auth.cpp)
    //---------------------------------------------

    //Stat methods

    //-----------------------------------------
    // Browsing functions (tdeio_smb_browse.cpp)
    //-----------------------------------------
    // (please prefix functions with browse)

    /**
     * Description :  Return a stat of given SMBUrl. Calls cache_stat and
     *                pack it in UDSEntry. UDSEntry will not be cleared
     * Parameter :    SMBUrl the url to stat
     *                ignore_errors do not call error(), but warning()
     * Return :       false if any error occoured (errno), else true
     */
    bool browse_stat_path(const SMBUrl& url, UDSEntry& udsentry, bool ignore_errors);

    /**
     * Description :  call smbc_stat and return stats of the url
     * Parameter :    SMBUrl the url to stat
     * Return :       stat* of the url
     * Note :         it has some problems with stat in method, looks like
     *                something leave(or removed) on the stack. If your
     *                method segfault on returning try to change the stat*
     *                variable
     */
    int cache_stat( const SMBUrl& url, struct stat* st );

    //---------------------------------------------
    // Configuration functions (tdeio_smb_config.cpp)
    //---------------------------------------------
    // (please prefix functions with config)


    //---------------------------------------
    // Directory functions (tdeio_smb_dir.cpp)
    //---------------------------------------
    // (please prefix functions with dir)


    //--------------------------------------
    // File IO functions (tdeio_smb_file.cpp)
    //--------------------------------------
    // (please prefix functions with file)

    //----------------------------
    // Misc functions (this file)
    //----------------------------


    /**
     * Description :  correct a given URL
     *                valid URL's are
     *
     *                smb://[[domain;]user[:password]@]server[:port][/share[/path[/file]]]
     *                smb:/[[domain;]user[:password]@][group/[server[/share[/path[/file]]]]]
     *                domain   = workgroup(domain) of the user
     *                user     = username
     *                password = password of useraccount
     *                group    = workgroup(domain) of server
     *                server   = host to connect
     *                share    = a share of the server (host)
     *                path     = a path of the share
     * Parameter :    KURL the url to check
     * Return :       new KURL if its corrected. else the same KURL
     */
    KURL checkURL(const KURL& kurl) const;

    void reportError(const SMBUrl &kurl);

public:

    //-----------------------------------------------------------------------
    // smbclient authentication callback (note that this is called by  the
    // global ::auth_smbc_get_data() call.
    void auth_smbc_get_data(const char *server,const char *share,
                            char *workgroup, int wgmaxlen,
                            char *username, int unmaxlen,
                            char *password, int pwmaxlen);


    //-----------------------------------------------------------------------
    // Overwritten functions from the base class that define the operation of
    // this slave. (See the base class headerfile slavebase.h for more
    // details)
    //-----------------------------------------------------------------------

    // Functions overwritten in tdeio_smb.cpp
    SMBSlave(const TQCString& pool, const TQCString& app);
    virtual ~SMBSlave();

    // Functions overwritten in tdeio_smb_browse.cpp
    virtual void listDir( const KURL& url );
    virtual void stat( const KURL& url );

    // Functions overwritten in tdeio_smb_config.cpp
    virtual void reparseConfiguration();

    // Functions overwritten in tdeio_smb_dir.cpp
    virtual void copy( const KURL& src, const KURL &dest, int permissions, bool overwrite );
    virtual void del( const KURL& kurl, bool isfile);
    virtual void mkdir( const KURL& kurl, int permissions );
    virtual void rename( const KURL& src, const KURL& dest, bool overwrite );

    // Functions overwritten in tdeio_smb_file.cpp
    virtual void get( const KURL& kurl );
    virtual void put( const KURL& kurl, int permissions, bool overwrite, bool resume );

    // Functions not implemented  (yet)
    //virtual void setHost(const TQString& host, int port, const TQString& user, const TQString& pass);
    //virtual void openConnection();
    //virtual void closeConnection();
    //virtual void slave_status();
    virtual void special( const TQByteArray & );

private slots:
    void readOutput(TDEProcess *proc, char *buffer, int buflen);
    void readStdErr(TDEProcess *proc, char *buffer, int buflen);

private:
    TQString mybuf, mystderr;

};

//===========================================================================
// pointer to the slave created in kdemain
extern SMBSlave* G_TheSlave;


//==========================================================================
// the global libsmbclient authentication callback function
extern "C"
{

void auth_smbc_get_data(const char *server,const char *share,
                        char *workgroup, int wgmaxlen,
                        char *username, int unmaxlen,
                        char *password, int pwmaxlen);

}


//===========================================================================
// Main slave entrypoint (see tdeio_smb.cpp)
extern "C"
{

int kdemain( int argc, char **argv );

}


#endif  //#endif TDEIO_SMB_H_INCLUDED
