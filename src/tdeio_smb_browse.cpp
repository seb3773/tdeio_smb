
/////////////////////////////////////////////////////////////////////////////
//
// Project:     SMB tdeioslave for KDE2
//
// File:        tdeio_smb_browse.cpp
//
// Abstract:    member function implementations for SMBSlave that deal with
//              SMB browsing
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

#include <config.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <tqtextcodec.h>

#include <tdeglobal.h>

#include "tdeio_smb.h"
#include "tdeio_smb_internal.h"
#include "smb_discovery.h"

using namespace TDEIO;

int SMBSlave::cache_stat(const SMBUrl &url, struct stat* st )
{
    int result = smbc_stat( url.toSmbcUrl(), st);
    kdDebug(TDEIO_SMB) << "smbc_stat " << url << " " << errno << " " << result << endl;
    kdDebug(TDEIO_SMB) << "size " << (TDEIO::filesize_t)st->st_size << endl;
    return result;
}

//---------------------------------------------------------------------------
bool SMBSlave::browse_stat_path(const SMBUrl& _url, UDSEntry& udsentry, bool ignore_errors)
  // Returns: true on success, false on failure
{
    UDSAtom     udsatom;

    SMBUrl url = _url;

   if(cache_stat(url, &st) == 0)
   {
      if(!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
      {
         kdDebug(TDEIO_SMB)<<"SMBSlave::browse_stat_path mode: "<<st.st_mode<<endl;
         warning(i18n("%1:\n"
                      "Unknown file type, neither directory or file.").arg(url.prettyURL()));
         return false;
      }

      udsatom.m_uds  = TDEIO::UDS_FILE_TYPE;
      udsatom.m_long = st.st_mode & S_IFMT;
      udsentry.append(udsatom);

      udsatom.m_uds  = TDEIO::UDS_SIZE;
      udsatom.m_long = st.st_size;
      udsentry.append(udsatom);

      udsatom.m_uds  = TDEIO::UDS_USER;
      uid_t uid = st.st_uid;
      struct passwd *user = getpwuid( uid );
      if ( user )
          udsatom.m_str = user->pw_name;
      else
          udsatom.m_str = TQString::number( uid );
      udsentry.append(udsatom);

      udsatom.m_uds  = TDEIO::UDS_GROUP;
      gid_t gid = st.st_gid;
      struct group *grp = getgrgid( gid );
      if ( grp )
          udsatom.m_str = grp->gr_name;
      else
          udsatom.m_str = TQString::number( gid );
      udsentry.append(udsatom);

      udsatom.m_uds  = TDEIO::UDS_ACCESS;
      udsatom.m_long = st.st_mode & 07777;
      udsentry.append(udsatom);

      udsatom.m_uds  = UDS_MODIFICATION_TIME;
      udsatom.m_long = st.st_mtime;
      udsentry.append(udsatom);

      udsatom.m_uds  = UDS_ACCESS_TIME;
      udsatom.m_long = st.st_atime;
      udsentry.append(udsatom);

      udsatom.m_uds  = UDS_CREATION_TIME;
      udsatom.m_long = st.st_ctime;
      udsentry.append(udsatom);

   }
   else
   {
        if (!ignore_errors) {
            if (errno == EPERM || errno == EACCES || errno == EINVAL)
                if (checkPassword(url)) {
                    redirection( url );
                    return false;
                }

            reportError(url);
        } else if (errno == ENOENT || errno == ENOTDIR) {
           warning(i18n("File does not exist: %1").arg(url.url()));
       }
       kdDebug(TDEIO_SMB) << "SMBSlave::browse_stat_path ERROR!!"<< endl;
       return false;
   }

   return true;
}

//===========================================================================
void SMBSlave::stat( const KURL& kurl )
{
    kdDebug(TDEIO_SMB) << "SMBSlave::stat on "<< kurl << endl;
    // make a valid URL
    KURL url = checkURL(kurl);

    // if URL is not valid we have to redirect to correct URL
    if (url != kurl)
    {
        kdDebug() << "redirection " << url << endl;
        redirection(url);
        finished();
        return;
    }

    m_current_url = url;

    UDSAtom     udsatom;
    UDSEntry    udsentry;
    // Set name
    udsatom.m_uds = TDEIO::UDS_NAME;
    udsatom.m_str = kurl.fileName();
    udsentry.append( udsatom );

    switch(m_current_url.getType())
    {
    case SMBURLTYPE_UNKNOWN:
        error(ERR_MALFORMED_URL,m_current_url.prettyURL());
        finished();
        return;

    case SMBURLTYPE_ENTIRE_NETWORK:
    case SMBURLTYPE_WORKGROUP_OR_SERVER:
        udsatom.m_uds = TDEIO::UDS_FILE_TYPE;
        udsatom.m_long = S_IFDIR;
        udsentry.append(udsatom);
        break;

    case SMBURLTYPE_SHARE_OR_PATH:
        if (browse_stat_path(m_current_url, udsentry, false))
            break;
        else {
            kdDebug(TDEIO_SMB) << "SMBSlave::stat ERROR!!"<< endl;
            finished();
            return;
        }
    default:
        kdDebug(TDEIO_SMB) << "SMBSlave::stat UNKNOWN " << url << endl;
        finished();
        return;
    }

    statEntry(udsentry);
    finished();
}

//===========================================================================
// TODO: complete checking
KURL SMBSlave::checkURL(const KURL& kurl) const
{
    kdDebug(TDEIO_SMB) << "checkURL " << kurl << endl;
    TQString surl = kurl.url();
    if (surl.startsWith("smb:/")) {
        if (surl.length() == 5) // just the above
            return kurl; // unchanged

        if (surl.at(5) != '/') {
            surl = "smb://" + surl.mid(5);
            kdDebug(TDEIO_SMB) << "checkURL return1 " << surl << " " << KURL(surl) << endl;
            return KURL(surl);
        }
    }

    // smb:/ normaly have no userinfo
    // we must redirect ourself to remove the username and password
    if (surl.contains('@') && !surl.contains("smb://")) {
        KURL url(kurl);
        url.setPath("/"+kurl.url().right( kurl.url().length()-kurl.url().find('@') -1));
        TQString userinfo = kurl.url().mid(5, kurl.url().find('@')-5);
        if(userinfo.contains(':'))  {
            url.setUser(userinfo.left(userinfo.find(':')));
            url.setPass(userinfo.right(userinfo.length()-userinfo.find(':')-1));
        } else {
            url.setUser(userinfo);
        }
        kdDebug(TDEIO_SMB) << "checkURL return2 " << url << endl;
        return url;
    }

    // no emtpy path
    KURL url(kurl);

    if (url.path().isEmpty())
        url.setPath("/");

    // If host matches a printer model name or display name, resolve it to NetBIOS name
    if (!url.host().isEmpty()) {
        TQString resolved = SMBDiscovery::resolveHostName(url.host());
        if (!resolved.isEmpty() && resolved != url.host()) {
            url.setHost(resolved);
        }
    }

    kdDebug(TDEIO_SMB) << "checkURL return3 " << url << endl;
    return url;
}

void SMBSlave::reportError(const SMBUrl &url)
{
    kdDebug(TDEIO_SMB) << "reportError " << url << " " << perror << endl;
    switch(errno)
    {
    case ENOENT:
        if (url.getType() == SMBURLTYPE_ENTIRE_NETWORK)
            error( ERR_SLAVE_DEFINED, i18n("Unable to find any workgroups in your local network. This might be caused by an enabled firewall."));
        else
            error( ERR_DOES_NOT_EXIST, url.prettyURL());
        break;
#ifdef ENOMEDIUM
    case ENOMEDIUM:
        error( ERR_SLAVE_DEFINED,
               i18n( "No media in device for %1" ).arg( url.prettyURL() ) );
        break;
#endif
#ifdef EHOSTDOWN
    case EHOSTDOWN:
#endif
    case ECONNREFUSED:
        error(  ERR_SLAVE_DEFINED,
                i18n( "Could not connect to host for %1" ).arg( url.prettyURL() ) );
        break;
    case ENOTDIR:
        error( ERR_CANNOT_ENTER_DIRECTORY, url.prettyURL());
        break;
    case EFAULT:
        error( ERR_DOES_NOT_EXIST, url.prettyURL());
        break;
    case EINVAL:
        error( ERR_ACCESS_DENIED, url.prettyURL() );
        break;
    case EPERM:
    case EACCES:
        error( ERR_ACCESS_DENIED, url.prettyURL() );
        break;
    case EIO:
    case ENETUNREACH:
        if ( url.getType() == SMBURLTYPE_ENTIRE_NETWORK || url.getType() == SMBURLTYPE_WORKGROUP_OR_SERVER )
            error( ERR_SLAVE_DEFINED, i18n( "Error while connecting to server responsible for %1" ).arg( url.prettyURL() ) );
        else
            error( ERR_CONNECTION_BROKEN, url.prettyURL());
        break;
    case ENOMEM:
        error( ERR_OUT_OF_MEMORY, url.prettyURL() );
        break;
    case ENODEV:
        error( ERR_SLAVE_DEFINED, i18n("Share could not be found on given server"));
        break;
    case EBADF:
        error( ERR_INTERNAL, i18n("BAD File descriptor"));
        break;
    case ETIMEDOUT:
        error( ERR_SERVER_TIMEOUT, url.host() );
        break;
#ifdef ENOTUNIQ
    case ENOTUNIQ:
        error( ERR_SLAVE_DEFINED, i18n( "The given name could not be resolved to a unique server. "
                                        "Make sure your network is setup without any name conflicts "
                                        "between names used by Windows and by UNIX name resolution." ) );
        break;
#endif
    case 0: // success
	  error( ERR_INTERNAL, i18n("libsmbclient reported an error, but did not specify "
								"what the problem is. This might indicate a severe problem "
								"with your network - but also might indicate a problem with "
								"libsmbclient.\n"
								"If you want to help us, please provide a tcpdump of the "
								"network interface while you try to browse (be aware that "
								"it might contain private data, so do not post it if you are "
								"unsure about that - you can send it privately to the developers "
								"if they ask for it)") );
	  break;
    default:
        error( ERR_INTERNAL, i18n("Unknown error condition in stat: %1").arg(TQString::fromLocal8Bit( strerror(errno))) );
    }
}

//===========================================================================
void SMBSlave::listDir( const KURL& kurl )
{
   kdDebug(TDEIO_SMB) << "SMBSlave::listDir on " << kurl << endl;

   // check (correct) URL
   KURL url = checkURL(kurl);
   // if URL is not valid we have to redirect to correct URL
   if (url != kurl)
   {
      redirection(url);
      finished();
      return;
   }

   m_current_url = kurl;

    // Modern discovery for entire network (smb:/) using WSDD + Avahi
    if (m_current_url.getType() == SMBURLTYPE_ENTIRE_NETWORK)
    {
        kdDebug(TDEIO_SMB) << "SMBSlave::listDir: SMBURLTYPE_ENTIRE_NETWORK -> modern discovery" << endl;
        TQValueList<SMBDiscoveredHost> hosts = SMBDiscovery::discoverHosts(false);

        // Count printer models to detect duplicate model names and disambiguate them
        TQMap<TQString, int> modelCounts;
        for (TQValueList<SMBDiscoveredHost>::ConstIterator it = hosts.begin(); it != hosts.end(); ++it) {
            if ((*it).isPrinter && !(*it).modelName.isEmpty()) {
                modelCounts[(*it).modelName] = modelCounts[(*it).modelName] + 1;
            }
        }

        UDSEntry udsentry;
        UDSAtom atom;

        for (TQValueList<SMBDiscoveredHost>::ConstIterator it = hosts.begin(); it != hosts.end(); ++it) {
            udsentry.clear();

            TQString displayName;
            if ((*it).isPrinter && !(*it).modelName.isEmpty()) {
                if (modelCounts[(*it).modelName] > 1) {
                    displayName = (*it).modelName + " (" + (*it).name + ")";
                } else {
                    displayName = (*it).modelName;
                }
            } else {
                displayName = (*it).name;
            }

            atom.m_uds = TDEIO::UDS_NAME;
            atom.m_str = displayName;
            udsentry.append(atom);

            atom.m_uds = TDEIO::UDS_FILE_TYPE;
            atom.m_long = S_IFDIR;
            udsentry.append(atom);

            atom.m_uds = TDEIO::UDS_ACCESS;
            atom.m_long = (S_IRUSR | S_IRGRP | S_IROTH | S_IXUSR | S_IXGRP | S_IXOTH);
            udsentry.append(atom);

            atom.m_uds = TDEIO::UDS_MIME_TYPE;
            if ((*it).isPrinter) {
                atom.m_str = TQString::fromLatin1("print/printer");
            } else {
                atom.m_str = TQString::fromLatin1("application/x-smb-server");
            }
            udsentry.append(atom);

            // Comment displayed under name in Konqueror
            TQString extra;
            if ((*it).isPrinter) {
                extra = (*it).name;
                if (!(*it).workgroup.isEmpty()) {
                    extra += " [" + (*it).workgroup + "]";
                }
            } else {
                if (!(*it).workgroup.isEmpty()) {
                    extra = (*it).workgroup;
                }
                if (!(*it).comment.isEmpty()) {
                    if (!extra.isEmpty()) extra += " - ";
                    extra += (*it).comment;
                }
            }
            if (!extra.isEmpty()) {
                atom.m_uds = TDEIO::UDS_EXTRA;
                atom.m_str = extra;
                udsentry.append(atom);
            }

            atom.m_uds = TDEIO::UDS_URL;
            KURL u;
            u.setProtocol("smb");
            u.setHost((*it).name);
            u.setPath("/");
            atom.m_str = u.url();
            udsentry.append(atom);

            listEntry(udsentry, false);
        }

        udsentry.clear();
        listEntry(udsentry, true);
        finished();
        return;
    }

   int                 dirfd;
   struct smbc_dirent  *dirp = NULL;
   UDSEntry    udsentry;
   UDSAtom     atom;

   dirfd = smbc_opendir( m_current_url.toSmbcUrl() );
   kdDebug(TDEIO_SMB) << "SMBSlave::listDir open " << m_current_url.toSmbcUrl() << " " << m_current_url.getType() << " " << dirfd << endl;
   if(dirfd >= 0)
   {
       do {
           kdDebug(TDEIO_SMB) << "smbc_readdir " << endl;
           dirp = smbc_readdir(dirfd);
           if(dirp == 0)
               break;

           // Set name
           atom.m_uds = TDEIO::UDS_NAME;
           TQString dirpName = TQString::fromUtf8( dirp->name );
           // We cannot trust dirp->commentlen has it might be with or without the NUL character
           // See KDE bug #111430 and Samba bug #3030
           TQString comment = TQString::fromUtf8( dirp->comment );
           if ( dirp->smbc_type == SMBC_SERVER || dirp->smbc_type == SMBC_WORKGROUP ) {
               atom.m_str = dirpName.lower();
               atom.m_str.at( 0 ) = dirpName.at( 0 ).upper();
               if ( !comment.isEmpty() && dirp->smbc_type == SMBC_SERVER )
                   atom.m_str += " (" + comment + ")";
           } else
               atom.m_str = dirpName;

           kdDebug(TDEIO_SMB) << "dirp->name " <<  dirp->name  << " " << dirpName << " '" << comment << "'" << " " << dirp->smbc_type << endl;

           udsentry.append( atom );
           if (atom.m_str.upper()=="IPC$" || atom.m_str=="." || atom.m_str == ".." ||
               atom.m_str.upper() == "ADMIN$" || atom.m_str.lower() == "printer$" || atom.m_str.lower() == "print$" )
           {
//            fprintf(stderr,"----------- hide: -%s-\n",dirp->name);
               // do nothing and hide the hidden shares
           }
           else if(dirp->smbc_type == SMBC_FILE)
           {
               // Set stat information
               m_current_url.addPath(dirpName);
               browse_stat_path(m_current_url, udsentry, true);
               m_current_url.cd("..");

               // Call base class to list entry
               listEntry(udsentry, false);
           }
           else if(dirp->smbc_type == SMBC_DIR)
           {
               m_current_url.addPath(dirpName);
               browse_stat_path(m_current_url, udsentry, true);
               m_current_url.cd("..");

               // Call base class to list entry
               listEntry(udsentry, false);
           }
           else if(dirp->smbc_type == SMBC_SERVER ||
                   dirp->smbc_type == SMBC_FILE_SHARE)
           {
               // Set type
               atom.m_uds = TDEIO::UDS_FILE_TYPE;
               atom.m_long = S_IFDIR;
               udsentry.append( atom );

               // Set permissions
               atom.m_uds  = TDEIO::UDS_ACCESS;
               atom.m_long = (S_IRUSR | S_IRGRP | S_IROTH | S_IXUSR | S_IXGRP | S_IXOTH);
               udsentry.append(atom);

               if (dirp->smbc_type == SMBC_SERVER) {
                   atom.m_uds = TDEIO::UDS_URL;
                   // TQString workgroup = m_current_url.host().upper();
                   KURL u("smb:/");
                   u.setHost(dirpName);
                   atom.m_str = u.url();

                   // when libsmbclient knows
                   // atom.m_str = TQString("smb://%1?WORKGROUP=%2").arg(dirpName).arg(workgroup.upper());
                   kdDebug(TDEIO_SMB) << "list item " << atom.m_str << endl;
                   udsentry.append(atom);

                   atom.m_uds = TDEIO::UDS_MIME_TYPE;
                   atom.m_str = TQString::fromLatin1("application/x-smb-server");
                   udsentry.append(atom);
               }

               // Call base class to list entry
               listEntry(udsentry, false);
            }
           else if(dirp->smbc_type == SMBC_WORKGROUP)
           {
               // Set type
               atom.m_uds = TDEIO::UDS_FILE_TYPE;
               atom.m_long = S_IFDIR;
               udsentry.append( atom );

               // Set permissions
               atom.m_uds  = TDEIO::UDS_ACCESS;
               atom.m_long = (S_IRUSR | S_IRGRP | S_IROTH | S_IXUSR | S_IXGRP | S_IXOTH);
               udsentry.append(atom);

               atom.m_uds = TDEIO::UDS_MIME_TYPE;
               atom.m_str = TQString::fromLatin1("application/x-smb-workgroup");
               udsentry.append(atom);

               atom.m_uds = TDEIO::UDS_URL;
               // TQString workgroup = m_current_url.host().upper();
               KURL u("smb:/");
               u.setHost(dirpName);
               atom.m_str = u.url();
               udsentry.append(atom);

               // Call base class to list entry
               listEntry(udsentry, false);
           }
           else
           {
               kdDebug(TDEIO_SMB) << "SMBSlave::listDir SMBC_UNKNOWN :" << dirpName << endl;
               // TODO: we don't handle SMBC_IPC_SHARE, SMBC_PRINTER_SHARE
               //       SMBC_LINK, SMBC_COMMS_SHARE
               //SlaveBase::error(ERR_INTERNAL, TEXT_UNSUPPORTED_FILE_TYPE);
               // continue;
           }
           udsentry.clear();
       } while (dirp); // checked already in the head

       // clean up
       smbc_closedir(dirfd);
   }
   else
   {
        if (errno == EPERM || errno == EACCES || errno == EINVAL)
            if (checkPassword(m_current_url)) {
                redirection( m_current_url );
                finished();
                return;
            }

        reportError(m_current_url);
       finished();
       return;
   }

   listEntry(udsentry, true);
   finished();
}

