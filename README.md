tlsclient - a simple to use TLS client library for Linux with special features

tlsclient is a TLS client library that can use OpenSSL, mbedTLS or
GnuTLS as a backend. As a difference to other libraries all three
mentioned backends can be enabled at compile time and backend
selection is possibe at runtime.

The tlsclient API is really very simple. For a very simple setup
(e.g. development) only 8 library calls are necessary, 3 of which
are for cleanup only. In practise you do:

* tls\_client\_global\_init
* tls\_client\_init
* tls\_client\_connect
* tls\_client\_write and tls\_client\_read
* tls\_client\_disconnect
* tls\_client\_fini
* tls\_client\_global\_fini

You can then go on to use certificate verification, 
retrieve the TLS version of an established connection, enable ALPN
or use client certificates. Related functions are:

* tls\_client\_add\_cafile
* tls\_client\_get\_tls\_version
* tls\_client\_set\_alpn
* tls\_client\_get\_alpn
* tls\_client\_add\_client\_cert

Note that for mbedTLS tls\_client\_get\_tls\_version depends on
MBEDTLS\_SSL\_RENEGOTIATION (compile time flag) to be the same as for the
version the tlsclient library was compiled against to actually work.
As this flag is usually enabled there should typically be no problem.

If you need to you can use session resumption by storing
session resume data during tls\_client\_disconnect() and reusing
them in a later tls\_client\_connect(). To get hinting about
resumption, resume data lifetime and to free the stored resume data use:

* tls\_client\_connection\_is\_resumed
* tls\_client\_resume\_data\_lifetime\_hint
* tls\_client\_free\_resume\_data

Note that definite resumption status is not available per default for mbedTLS
and must be explicitely compile time enabled, as using this functionality
breaks binary compatability of the tlsclient library and any mbedTLS
library the tlsclient library was not compiled against. The other implemented
way should be binary compatible but doesn't detect resumption in case of
self signed certificates.

The following paragraph about OCSP is not valid for the mbedTLS
backend which does not support any form of OCSP processing.

OCSP status responses received from the accessed server are
validated by default if certificate chain checking is enabled.
This behaviour and thus OCSP verification can be disabled.
If a connect callback is configured, OCSP verification is
enabled, the server does not provide an OCSP status and the
server certificate contains an http protocol OCSP URI,
the library will try to fetch the OCSP data from the server
specified in the OCSP URI. If fetching the data or OCSP verifying
fails the requested TLS connection attempt will be aborted.
Note that it doesn't make really sense for https to be used for
an OCSP server: the server certificate would then need to be
verified, resulting in a subsequent OCSP verification which may
result in another OCSP data fetching attempt... - the result
may be an endless loop. Furthermore note that externally fetched
OCSP data are not cached. Related functions are:

* tls\_client\_set\_ocsp\_connect\_callback 
* tls\_client\_set\_oscp\_verification

As a special feature the library can use patched versions of
OpenSSL and GnuTLS to emulate the TLS Client Hello messages
of common browsers. The required patches as well as a build
system for these is supplied, you only need to download the
required backend library to be patched. For simple use cases
some emulations are completely integrated in the library
and can be accessed using the high level functions:

* tls\_client\_emulation\_init
* tls\_client\_emulation\_connect

When non-standard templates shall be used or new emulations
are to be developed the low level interface should be used.
Related functions are:

* tls\_client\_load\_hello\_template
* tls\_client\_use\_hello\_template
* tls\_client\_get\_emulation\_error
* tls\_client\_get\_max\_tls\_version
* tls\_client\_set\_max\_tls\_version

The usage of the emulation is best demonstrated with the included tester
(it is expected that you have regular versions of the patched libraries
installed on your system in standard locations and the patched versions
reside in their respective build directories):

* Emulate Chromium 84 Linux and connect to localhost port 443 (requires patched OpenSSL):
* ./tester -L openssl:gnutls -N chromium84lx localhost
* Emulate Firefox 78 Linux and connect to localhost port 443 (requires patched GnuTLS):
* ./tester -L openssl:gnutls -N firefox78lx localhost

If you want to create a new emulation you should have a look, what the
high level emulation code does. The reason for this is that browsers do
special things behind the scenes which you may want to emulate, too.

If you want to create a new emulation, the tlshelloanalyzer tool is what
you need to create a new template and to analyze, what you are doing.
The tester will be of use in this case too with the options to use an
emulation by number and to specifiy the required backend library.
A little bit of thinking and coding will be required, though.
The proper backend has to be selected first based on the TLS Client
Hello message of the desired emulation target and then the backend
has to be nudged to get functionality wise as close to the desired
target as possible before the emulation template can be put to use.

If you don't want or need the emulation, you can build the library
without it. Just set the proper option in the Makefile.

The library does session resumption only if session tickets are used.
The old resumption method based on session id is probably rarely used
nowadays and as all security data are stored in one place can be
considered a security risk.

The resulting libtlsclient.so shared library as well as the
required tlsclient.h header file are licensed LGPLv2.1+,
the patches for OpenSSL and GnuTLS are licensed as the library
to be patched, template configuration files (template directory)
as well as regression samples (regression directory) are free of
any license, everything else is licensed GPLv2+.
