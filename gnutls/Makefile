# This file is part of the tlsclient project
# 
# (C) 2020 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
# GnuTLS Version
VER=3.6.14
#
# Library so Version
LIBVER=30.28.0
#
# modifyable options
CERTSTORE=/etc/ssl/certs/ca-certificates.crt
OPTS=--prefix=/usr --libdir=/usr/lib64 --sysconfdir=/etc
OPTS+=--localstatedir=/var --enable-cxx --enable-openssl-compatibility
OPTS+=--with-idn --with-default-trust-store-file=$(CERTSTORE)
OPTS+=--without-included-libtasn1 --without-tpm --disable-doc --disable-tools
OPTS+=--disable-nls --disable-rpath

all: gnutls-$(VER) libgnutls.so.$(LIBVER)

libgnutls.so.$(LIBVER): gnutls-$(VER)/lib/.libs/libgnutls.so.$(LIBVER)
	ln -sf libgnutls.so.$(LIBVER) \
		libgnutls.so.`echo $(LIBVER) | cut -d. -f1`
	cp $< $@

gnutls-$(VER)/lib/.libs/libgnutls.so.$(LIBVER): gnutls-$(VER)/Makefile
	make -C gnutls-$(VER)

gnutls-$(VER)/Makefile: gnutls-$(VER)/lib/clienthello.h
	cd gnutls-$(VER) ; ./configure $(OPTS)

gnutls-$(VER)/lib/clienthello.h: gnutls-$(VER)-clienthello.patch
	cd gnutls-$(VER) ; patch -p1 < ../gnutls-$(VER)-clienthello.patch
	touch gnutls-$(VER)/lib/handshake.c

gnutls-$(VER):
	tar xf gnutls-$(VER).tar.*

gnutls-$(VER)-clienthello.patch: gnutls-$(VER)-clienthello.patch.in obfuscate
	./obfuscate -o $@ -i $< -f tls_client_hello_modify -v V_1_0

obfuscate: obfuscate.c
	gcc -Wall -O2 -o obfuscate obfuscate.c

clean:
	rm -rf gnutls-$(VER) libgnutls.so.$(LIBVER) obfuscate \
		libgnutls.so.`echo $(LIBVER) | cut -d. -f1` \
		gnutls-$(VER)-clienthello.patch
