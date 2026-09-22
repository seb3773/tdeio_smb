/*  This file is part of the KDE project

    Copyright (C) 2000 Alexander Neundorf <neundorf@kde.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#include "tdeio_smb.h"
#include <kstandarddirs.h>
#include <tqcstring.h>
#include <unistd.h>
#include <tqdir.h>
#include <kprocess.h>

void SMBSlave::readOutput(TDEProcess *, char *buffer, int buflen)
{
    mybuf += TQString::fromLocal8Bit(buffer, buflen);
}

void SMBSlave::readStdErr(TDEProcess *, char *buffer, int buflen)
{
    mystderr += TQString::fromLocal8Bit(buffer, buflen);
}

void SMBSlave::special( const TQByteArray & data)
{
   kdDebug(TDEIO_SMB)<<"Smb::special()"<<endl;
   int tmp;
   TQDataStream stream(data, IO_ReadOnly);
   stream >> tmp;
   //mounting and umounting are both blocking, "guarded" by a SIGALARM in the future
   switch (tmp)
   {
   case 1:
   case 3:
      {
         TQString remotePath, mountPoint, user;
         stream >> remotePath >> mountPoint;

         TQStringList sl=TQStringList::split("/",remotePath);
         TQString share,host;
         if (sl.count()>=2)
         {
            host=(*sl.at(0)).mid(2);
            share=(*sl.at(1));
            kdDebug(TDEIO_SMB)<<"special() host -"<< host <<"- share -" << share <<"-"<<endl;
         }

         remotePath.replace('\\', '/');  // smbmounterplugin sends \\host/share

         kdDebug(TDEIO_SMB) << "mounting: " << remotePath.local8Bit() << " to " << mountPoint.local8Bit() << endl;

         if (tmp==3) {
             if (!TDEStandardDirs::makeDir(mountPoint)) {
                 error(TDEIO::ERR_COULD_NOT_MKDIR, mountPoint);
                 return;
             }
         }
         mybuf.truncate(0);
         mystderr.truncate(0);

         SMBUrl smburl("smb:///");
         smburl.setHost(host);
         smburl.setPath("/" + share);

         if ( !checkPassword(smburl) )
         {
           finished();
           return;
         }

         // using smbmount instead of "mount -t smbfs", because mount does not allow a non-root
         // user to do a mount, but a suid smbmnt does allow this

         TDEProcess proc;
         proc.setUseShell(true);  // to have the path to smbmnt (which is used by smbmount); see man smbmount
         proc << "smbmount";

         TQString options;

         if ( smburl.user().isEmpty() )
         {
           user = "guest";
           options = "-o guest";
         }
         else
         {
           options = "-o username=" + TDEProcess::quote(smburl.user());
           user = smburl.user();

           if ( ! smburl.pass().isEmpty() )
             options += ",password=" + TDEProcess::quote(smburl.pass());
         }

         // TODO: check why the control center uses encodings with a blank char, e.g. "cp 1250"
         //if ( ! m_default_encoding.isEmpty() )
           //options += ",codepage=" + TDEProcess::quote(m_default_encoding);

         proc << TDEProcess::quote(remotePath.local8Bit());
         proc << TDEProcess::quote(mountPoint.local8Bit());
         proc << options;

         connect(&proc, TQT_SIGNAL( receivedStdout(TDEProcess *, char *, int )),
                 TQT_SLOT(readOutput(TDEProcess *, char *, int)));

         connect(&proc, TQT_SIGNAL( receivedStderr(TDEProcess *, char *, int )),
                 TQT_SLOT(readStdErr(TDEProcess *, char *, int)));

         if (!proc.start( TDEProcess::Block, TDEProcess::AllOutput ))
         {
            error(TDEIO::ERR_CANNOT_LAUNCH_PROCESS,
                  "smbmount"+i18n("\nMake sure that the samba package is installed properly on your system."));
            return;
         }

         kdDebug(TDEIO_SMB) << "mount exit " << proc.exitStatus() << endl
                          << "stdout:" << mybuf << endl << "stderr:" << mystderr << endl;

         if (proc.exitStatus() != 0)
         {
           error( TDEIO::ERR_COULD_NOT_MOUNT,
               i18n("Mounting of share \"%1\" from host \"%2\" by user \"%3\" failed.\n%4")
               .arg(share).arg(host).arg(user).arg(mybuf + "\n" + mystderr));
           return;
         }

         finished();
      }
      break;
   case 2:
   case 4:
      {
         TQString mountPoint;
         stream >> mountPoint;

         TDEProcess proc;
         proc.setUseShell(true);
         proc << "smbumount";
         proc << TDEProcess::quote(mountPoint);

         mybuf.truncate(0);
         mystderr.truncate(0);

         connect(&proc, TQT_SIGNAL( receivedStdout(TDEProcess *, char *, int )),
                 TQT_SLOT(readOutput(TDEProcess *, char *, int)));

         connect(&proc, TQT_SIGNAL( receivedStderr(TDEProcess *, char *, int )),
                 TQT_SLOT(readStdErr(TDEProcess *, char *, int)));

         if ( !proc.start( TDEProcess::Block, TDEProcess::AllOutput ) )
         {
           error(TDEIO::ERR_CANNOT_LAUNCH_PROCESS,
                 "smbumount"+i18n("\nMake sure that the samba package is installed properly on your system."));
           return;
         }

         kdDebug(TDEIO_SMB) << "smbumount exit " << proc.exitStatus() << endl
                          << "stdout:" << mybuf << endl << "stderr:" << mystderr << endl;

         if (proc.exitStatus() != 0)
         {
           error(TDEIO::ERR_COULD_NOT_UNMOUNT,
               i18n("Unmounting of mountpoint \"%1\" failed.\n%2")
               .arg(mountPoint).arg(mybuf + "\n" + mystderr));
           return;
         }

         if ( tmp == 4 )
         {
           bool ok;

           TQDir dir(mountPoint);
           dir.cdUp();
           ok = dir.rmdir(mountPoint);
           if ( ok )
           {
             TQString p=dir.path();
             dir.cdUp();
             ok = dir.rmdir(p);
           }

           if ( !ok )
           {
             error(TDEIO::ERR_COULD_NOT_RMDIR, mountPoint);
             return;
           }
         }

         finished();
      }
      break;
   default:
      break;
   }
   finished();
}

#include "tdeio_smb.moc"
