# This file is part of the tlsclient project
#
# (C) 2020 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
# =============================================================================
#
# select any or all of the following libraries (selet at least one)
#
# OpenSSL 1.1 or later
#
OPENSSL=1
#
# mbedTLS 2.16 / 2.23 or later
#
MBEDTLS=1
#
# GnuTLS 3.5 or later
#
GNUTLS=1
#
# define if you want to test http2 data transfer
#
HTTP2=1
#
# define if you want to build without client hello emulation
#
#NO_EMULATION=1
#
# installation directories for library and header file
#
LIBDIR=/usr/local/lib64
HDRDIR=/usr/local/include
#
# compiler and flags
#
CC=gcc
CFLAGS=-O2
LFLAGS=-s
#
# enable the to actually remove all unreferenced code:
#
CFLAGS+=-fdata-sections -ffunction-sections
LFLAGS+=-Wl,-gc-sections
#
# enable to enable the link time optimizer
#
CFLAGS+=-flto
LFLAGS+=-flto -fuse-linker-plugin
#
# =============================================================================
#                  no user selectable stuff below this line
# =============================================================================
#
LIBS=
LIBOBJS=
LIBTST=
LIBVER=1
SOFLAGS=-Wl,-soname,libtlsclient.so.$(LIBVER)
ifdef OPENSSL
SSLWRAP=1
CFLAGS+=-DUSE_OPENSSL
LIBS+=-lssl -lcrypto
LIBOBJS+=tlsclient-openssl.lo
endif
ifdef MBEDTLS
SSLWRAP=1
CFLAGS+=-DUSE_MBEDTLS
LIBS+=-lmbedtls -lmbedx509 -lmbedcrypto
LIBOBJS+=tlsclient-mbedtls.lo
endif
ifdef GNUTLS
SSLWRAP=1
CFLAGS+=-DUSE_GNUTLS
LIBS+=-lgnutls
LIBOBJS+=tlsclient-gnutls.lo
endif
ifdef SSLWRAP
TARGETS=libtlsclient.so tester
LIBOBJS+=tlsclient-common.lo tlsclient-emu.lo
TOOLOBJS=analyze.o clientdissect.o clientdump.o clienttables.o
else
$(error error no tls library selected!)
endif
ifdef NO_EMULATION
CFLAGS+=-DNO_EMU
TDEPS=
CDEPS=
else
TARGETS+=tlshelloanalyzer
LIBOBJS+=clientdissect.lo clientloader.lo
LIBOBJS+=clientconstruct.lo clientcompose.lo clienttables.lo
TDEPS=clientdata.h clientloader.h clientdissect.h
TDEPS+=chromium_84_11.hh chromium_84_12.hh chromium_84_2.hh chromium_84_31.hh
TDEPS+=chromium_84_32.hh
TDEPS+=firefox_78_1.hh firefox_78_22.hh firefox_78_23.hh
TDEPS+=konqueror_50_1.hh konqueror_50_2.hh konqueror_50_31.hh konqueror_50_32.hh
TDEPS+=firefox_68a10_1.hh firefox_68a10_22.hh firefox_68a10_23.hh
TDEPS+=firefox_68a10_31.hh firefox_68a10_32.hh
TDEPS+=kiwi_77a10_11.hh kiwi_77a10_12.hh kiwi_77a10_2.hh kiwi_77a10_3.hh
CDEPS=clientdata.h clientdissect.h clientconstruct.h clientcompose.h
CDEPS+=clientloader.h
ifdef OPENSSL
ifdef GNUTLS
ifdef HTTP2
TARGETS+=regressor
RGOBJS=regressor.o clientdissect.o clientdump.o clienttables.o
LIBRGR=-lpthread -lnghttp2
RDEPS=regression/brave_1_10_linux.h regression/brave_1_11_android_10.h
RDEPS+=regression/chrome_84_android_10.h regression/chromium_84_linux.h
RDEPS+=regression/firefox_68_android_10.h regression/firefox_78_linux.h
RDEPS+=regression/kiwi_77_android_10.h regression/konqueror_5_0_linux.h
RDEPS+=regression/opera_59_android_10.h regression/opera_69_linux.h
RDEPS+=regression/vivaldi_3_1_android_10.h
endif
endif
endif
endif
ifdef HTTP2
CFLAGS+=-DHTTP2
LIBTST=-lnghttp2
endif

all: $(TARGETS)

libtlsclient.so: $(LIBOBJS)
	$(CC) $(LFLAGS) $(SOFLAGS) -shared -Wl,--version-script,tlsclient.map \
		-o $@ $(LIBOBJS) $(LIBS)

regressor: $(RGOBJS) libtlsclient.so
	$(CC) $(LFLAGS) -o $@ $(RGOBJS) $(LIBRGR) -L. -ltlsclient -Wl,-rpath,. \
		-Wl,-rpath,openssl -Wl,-rpath,gnutls

tlshelloanalyzer: $(TOOLOBJS)
	$(CC) $(LFLAGS) -o $@ $^

tester: tester.o libtlsclient.so
	$(CC) $(LFLAGS) -o $@ $< $(LIBTST) -L. -ltlsclient -Wl,-rpath,.

clean:
	rm -f *.o *.lo *.hh libtlsclient.so tlshelloanalyzer tester regressor

install: all
	install -m 755 libtlsclient.so $(LIBDIR)/libtlsclient.so.$(LIBVER)
	ln -sf libtlsclient.so.$(LIBVER) $(LIBDIR)/libtlsclient.so
	install -m 644 tlsclient.h $(HDRDIR)/tlsclient.h

tester.o: tester.c tlsclient.h clientdata.h clientdissect.h clientdump.h
tlsclient-common.lo: tlsclient-common.c tlsdispatch.h tlsclient.h $(CDEPS)
tlsclient-emu.lo: tlsclient-emu.c tlsclient.h tlsdispatch.h $(TDEPS)
tlsclient-openssl.lo: tlsclient-openssl.c tlsdispatch.h tlsclient.h
tlsclient-mbedtls.lo: tlsclient-mbedtls.c tlsdispatch.h tlsclient.h
tlsclient-gnutls.lo: tlsclient-gnutls.c tlsdispatch.h tlsclient.h
clientdissect.lo: clientdissect.c clientdissect.h clientdata.h
clientdissect.o: clientdissect.c clientdissect.h clientdata.h
clientloader.lo: clientloader.c clientloader.h clientdata.h clientdissect.h \
		clienttables.h
clientconstruct.lo: clientconstruct.c clientconstruct.h clientdata.h
clientcompose.lo: clientcompose.c clientcompose.h clientdata.h
clienttables.lo: clienttables.c clienttables.h
clienttables.o: clienttables.c clienttables.h
clientdump.o: clientdump.c clientdump.h clientdata.h clienttables.h \
	clientdissect.h
analyze.o: analyze.c clientdata.h clientdissect.h clientdump.h
regressor.o: regressor.c $(RDEPS)

%.lo : %.c
	$(CC) -fPIC -Wall $(CFLAGS) -o $*.lo -c $<

%.o : %.c
	$(CC) -Wall $(CFLAGS) -c $<

%.hh : templates/%.conf
	sed -n -f tmplconf.sed $< | sed -e '1s/.*/static const char $*[]=\n&/' \
		-e '$$s/.*/&;/' > $@
