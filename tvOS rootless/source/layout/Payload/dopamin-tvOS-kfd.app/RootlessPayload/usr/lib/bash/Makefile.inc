#
# Sample makefile for bash loadable builtin development
#
# Copyright (C) 2015-2022 Free Software Foundation, Inc.     

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

PACKAGE = bash
VERSION = 5.2-release

PACKAGE_NAME = bash
PACKAGE_VERSION = 5.2-release

# Include some boilerplate Gnu makefile definitions.
prefix = /usr

exec_prefix = ${prefix}
bindir = /usr/bin
libdir = ${exec_prefix}/lib
infodir = ${datarootdir}/info
includedir = ${prefix}/include

datarootdir = ${prefix}/share

loadablesdir = ${libdir}/bash
headersdir = $(includedir)/$(PACKAGE_NAME)

topdir = ../..
BUILD_DIR = /Users/nick/Developer/Procursus/build_work/appletvos-arm64/2000/bash
srcdir = .


# Support an alternate destination root directory for package building
DESTDIR =

INSTALL = /opt/procursus/libexec/gnubin/install --strip-program=/usr/bin/strip
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALLMODE= -m 0755


CC = /Applications/Xcode-15.2.0.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc
RM = rm -f

SHELL = /bin/sh

host_os = darwin
host_cpu = aarch64
host_vendor = apple

CFLAGS = -Os -flto=thin -arch arm64 -isysroot /Applications/Xcode-15.2.0.app/Contents/Developer/Platforms/AppleTVOS.platform/Developer/SDKs/AppleTVOS17.2.sdk -mappletvos-version-min=17.0 -isystem/Applications/Xcode-15.2.0.app/Contents/Developer/Platforms/AppleTVOS.platform/Developer/SDKs/AppleTVOS17.2.sdk/usr/include/c++/v1 -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/include/c++/v1 -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/include -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/local/include/c++/v1 -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/local/include -F/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/System/Library/Frameworks -F/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/Library/Frameworks -DSSH_SOURCE_BASHRC
LOCAL_CFLAGS = -DMACOSX
DEFS = -DHAVE_CONFIG_H
LOCAL_DEFS = -DSHELL

CPPFLAGS = -arch arm64 -mappletvos-version-min=17.0 -isysroot /Applications/Xcode-15.2.0.app/Contents/Developer/Platforms/AppleTVOS.platform/Developer/SDKs/AppleTVOS17.2.sdk -isystem/Applications/Xcode-15.2.0.app/Contents/Developer/Platforms/AppleTVOS.platform/Developer/SDKs/AppleTVOS17.2.sdk/usr/include/c++/v1 -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/include/c++/v1 -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/include -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/local/include/c++/v1 -isystem/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/local/include

BASHINCDIR = ${topdir}/include

SUPPORT_SRC = $(topdir)/support/

LIBBUILD = ${BUILD_DIR}/lib

INTL_LIBSRC = ${topdir}/lib/intl
INTL_BUILDDIR = ${LIBBUILD}/intl
INTL_INC = 
LIBINTL_H = 

CCFLAGS = $(DEFS) $(LOCAL_DEFS) $(LOCAL_CFLAGS) $(CFLAGS)

#
# These values are generated for configure by ${topdir}/support/shobj-conf.
# If your system is not supported by that script, but includes facilities for
# dynamic loading of shared objects, please update the script and send the
# changes to bash-maintainers@gnu.org.
#
SHOBJ_CC = /Applications/Xcode-15.2.0.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc
SHOBJ_CFLAGS = -fno-common
SHOBJ_LD = ${CC}
SHOBJ_LDFLAGS = -dynamiclib -dynamic -undefined dynamic_lookup  -Os -flto=thin -arch arm64 -isysroot /Applications/Xcode-15.2.0.app/Contents/Developer/Platforms/AppleTVOS.platform/Developer/SDKs/AppleTVOS17.2.sdk -mappletvos-version-min=17.0 -L/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/lib -L/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/usr/local/lib -F/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/System/Library/Frameworks -F/Users/nick/Developer/Procursus/build_base/appletvos-arm64/2000/Library/Frameworks -Wl,-not_for_dyld_shared_cache -liosexec
SHOBJ_XLDFLAGS = 
SHOBJ_LIBS = 
SHOBJ_STATUS = supported

INC = -I$(headersdir) -I$(headersdir)/include -I$(headersdir)/builtins

.c.o:
	$(SHOBJ_CC) $(SHOBJ_CFLAGS) $(CCFLAGS) $(INC) -c -o $@ $<
