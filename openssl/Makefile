# This file is part of the tlsclient project
# 
# (C) 2020 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
# OpenSSL Version
VER=1.1.1g
#
# Library so Version
LIBVER=1.1
#
# MUST enable for emulation
OPTS=shared enable-ec enable-weak-ssl-ciphers
#
# modifyable options
OPTS+=enable-camellia enable-srp enable-idea enable-mdc2 enable-rc5 zlib threads
OPTS+=no-tests

all: openssl-$(VER) libssl.so.$(LIBVER)

libssl.so.$(LIBVER): openssl-$(VER)/libssl.so.$(LIBVER)
	cp $< $@

openssl-$(VER)/libssl.so.$(LIBVER): openssl-$(VER)/Makefile
	make -C openssl-$(VER)

openssl-$(VER)/Makefile: openssl-$(VER)/ssl/clienthello.h
	cd openssl-$(VER) ; ./config --prefix=/usr --openssldir=/etc/ssl $(OPTS)

openssl-$(VER)/ssl/clienthello.h: openssl-$(VER)-clienthello.patch
	cd openssl-$(VER) ; patch -p1 < ../openssl-$(VER)-clienthello.patch

openssl-$(VER):
	tar xf openssl-$(VER).tar.*

openssl-$(VER)-clienthello.patch: openssl-$(VER)-clienthello.patch.in obfuscate
	./obfuscate -o $@ -i $< -f tls_client_hello_modify -v V_1_0

obfuscate: obfuscate.c
	gcc -Wall -O2 -o obfuscate obfuscate.c

clean:
	rm -rf openssl-$(VER) libssl.so.$(LIBVER) obfuscate \
		openssl-$(VER)-clienthello.patch
