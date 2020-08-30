/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GNU Lesser General
 * Public License, version 2.1 or, at your choice, any later version of
 * this license.
 */

#ifndef _TLS_CLIENT_H_INCLUDED
#define _TLS_CLIENT_H_INCLUDED

/*
 * backend library to use, any means use first compiled in library
 */

#define TLS_CLIENT_LIBRARY_ANY			0x00000000
#define TLS_CLIENT_LIBRARY_OPENSSL		0x01000000
#define TLS_CLIENT_LIBRARY_MBEDTLS		0x02000000
#define TLS_CLIENT_LIBRARY_GNUTLS		0x03000000

/*
 * tls version definitions, should be self explaining - TLSv1.1 cannot
 * be selected and is only returned
 */

#define TLS_CLIENT_TLS_1_0			0x00000000
#define TLS_CLIENT_TLS_1_1			0x00010000
#define TLS_CLIENT_TLS_1_2			0x00020000
#define TLS_CLIENT_TLS_1_3			0x00030000

/*
 * operation mode of OSCP verification (default on)
 */

#define TLS_CLIENT_OCSP_VERIFICATION_ON		0
#define TLS_CLIENT_OCSP_VERIFICATION_OFF	1

/*
 * emulation selection, high level interface
 */

#define TLS_CLIENT_EMULATION_CHROMIUM_84_LINUX		0
#define TLS_CLIENT_EMULATION_OPERA_69_LINUX		1
#define TLS_CLIENT_EMULATION_FIREFOX_78_LINUX		2
#define TLS_CLIENT_EMULATION_FIREFOX_79_LINUX \
	TLS_CLIENT_EMULATION_FIREFOX_78_LINUX
#define TLS_CLIENT_EMULATION_FIREFOX_80_LINUX \
	TLS_CLIENT_EMULATION_FIREFOX_78_LINUX
#define TLS_CLIENT_EMULATION_KONQUEROR_5_O_LINUX	3
#define TLS_CLIENT_EMULATION_FIREFOX_68_ANDROID_10	4
#define TLS_CLIENT_EMULATION_KIWI_77_ANDROID_10		5
#define TLS_CLIENT_EMULATION_VIVALDI_31_ANDROID_10	6
#define TLS_CLIENT_EMULATION_OPERA_59_ANDROID_10	7
#define TLS_CLIENT_EMULATION_CHROME_84_ANDROID_10	8
#define TLS_CLIENT_EMULATION_BRAVE_110_LINUX		9
#define TLS_CLIENT_EMULATION_BRAVE_112_LINUX \
	TLS_CLIENT_EMULATION_BRAVE_110_LINUX
#define TLS_CLIENT_EMULATION_BRAVE_111_ANDROID_10	10
#define TLS_CLIENT_EMULATION_OPERA_70_LINUX		11
#define TLS_CLIENT_EMULATION_FIREFOX_79_ANDROID_10	12
#define TLS_CLIENT_EMULATION_BRAVE_112_ANDROID_10	13
#define TLS_CLIENT_EMULATION_VIVALDI_32_ANDROID_10	14
#define TLS_CLIENT_EMULATION_CHROMIUM_85_LINUX		15

/*
 * emulation processing mode, high level interface
 */

#define TLS_CLIENT_EMULATION_STRICT			0
#define TLS_CLIENT_EMULATION_LOOSE			1

/*
 * template group selection for hello emulation, low level interface
 */

#define TLS_CLIENT_EMU_TEMPLATE_GROUP_OFF	-1
#define TLS_CLIENT_EMU_TEMPLATE_GROUP_1		0
#define TLS_CLIENT_EMU_TEMPLATE_GROUP_2		1
#define TLS_CLIENT_EMU_TEMPLATE_GROUP_3		2
#define TLS_CLIENT_EMU_TEMPLATE_GROUP_4		3

/*
 * tls hello emulation definitions - must match the loaded templates,
 * low level interface
 */

#define TLS_CLIENT_EMU_NONE			0x00000000
#define TLS_CLIENT_EMU_CHROMIUM_84_LINUX \
	(TLS_CLIENT_LIBRARY_OPENSSL|TLS_CLIENT_TLS_1_0|0x00000001)
#define TLS_CLIENT_EMU_FIREFOX_78_LINUX \
	(TLS_CLIENT_LIBRARY_GNUTLS|TLS_CLIENT_TLS_1_0|0x00000002)
#define TLS_CLIENT_EMU_FIREFOX_68_ANDROID_10 \
	TLS_CLIENT_EMU_FIREFOX_78_LINUX
#define TLS_CLIENT_EMU_FIREFOX_79_ANDROID_10 \
	TLS_CLIENT_EMU_FIREFOX_78_LINUX
#define TLS_CLIENT_EMU_KONQUEROR_5_O_LINUX \
	(TLS_CLIENT_LIBRARY_OPENSSL|TLS_CLIENT_TLS_1_0|0x00000003)
#define TLS_CLIENT_EMU_KIWI_77_ANDROID_10 \
	(TLS_CLIENT_LIBRARY_OPENSSL|TLS_CLIENT_TLS_1_0|0x00000004)

/*
 * tls emulation options depending on the selected emulation (bitwise or),
 * low level interface
 */

#define TLS_CLIENT_EMU_NO_OPTION		0x00000000
#define TLS_CLIENT_EMU_USE_STATIC_GREASE	0x00000001
#define TLS_CLIENT_EMU_NO_CERT_BROTLI		0x00000002
#define TLS_CLIENT_EMU_NO_CHANNEL_ID		0x00000004
#define TLS_CLIENT_EMU_FF68A10_RETRY		0x00000008

/*
 * tls emulation status (see description below), low level interface
 */

#define TLS_CLIENT_EMU_STATUS_OPTION_ERROR	0x00000800
#define TLS_CLIENT_EMU_STATUS_MODIFY_ERROR	0x00000400
#define TLS_CLIENT_EMU_STATUS_TX_ERROR		0x00000200
#define TLS_CLIENT_EMU_STATUS_RX_ERROR		0x00000100
#define TLS_CLIENT_EMU_STATUS_TX_COUNT		0x000000f0
#define TLS_CLIENT_EMU_STATUS_RX_COUNT		0x0000000f

/*
 * tls_client_global_init
 *
 * call once at application start, returns 0 in case of success and
 * -1 in case of an error
 */

extern int tls_client_global_init(void);

/*
 * tls_client_global_fini
 *
 * call once before application end
 */

extern void tls_client_global_fini(void);

/*
 * tls_client_init
 *
 * mode - a bitwise or if selected tls library, tls version and emulation id
 *
 * initialize common connection parameters, returns a pointer to
 * the common paramters or NULL in case of an error
 */

extern void *tls_client_init(int mode);

/*
 * tls_client_emulation_init
 *
 * emulation - a high level emulation selector (see definitions above)
 * strict    - the high level processing mode (see definitions above)
 *
 *	       TLS_CLIENT_EMULATION_STRICT means that the emulation
 *	       adheres byte for byte to the original and fails if a
 *	       server does support a TLS extension the emulation only
 *             pretended to support.
 *
 *	       TLS_CLIENT_EMULATION_LOOSE means that the emulation does
 *	       not adhere byte by byte to the original, TLS extensions
 *	       that cannot be handled locally are not pretended to
 *	       be supported.
 *
 *	       returns pointer to the common paramters or NULL in case
 *	       of an error
 */

extern void *tls_client_emulation_init(int emulation,int strict);

/*
 * tls_client_fini
 *
 * release common connection parameters, must always be called
 * after a successful call to tls_client_init if the common
 * connection parameters are no longer required
 */

extern void tls_client_fini(void *context);

/*
 * get the currently configured highest TLS version supported,
 * usually not required, mostly for emulation use
 */

extern int tls_client_get_max_tls_version(void *context);

/*
 * set the currently configured highest TLS version supported,
 * usually not required, mostly for emulation use
 */

extern int tls_client_set_max_tls_version(void *context,int version);

/*
 * tls_client_add_cafile
 *
 * add the contents of <fn> to the list of trusted CAs, context
 * is a pointer to common connection parameters, the CA file
 * can contain one or more CAs in PEM format, returns 0 in case
 * of (partial) success and -1 in case of an error
 */

extern int tls_client_add_cafile(void *context,char *fn);

/*
 * set connect callback for OCSP verification - if not set no OCSP
 * verification takes place in case the server certificate presented
 * by the peer contains an OCSP URI but the server doesn't provide
 * OCSP data. Note that only http URIs (i.e. no https) are processed,
 * other URIs are ignored.
 */

extern void tls_client_set_ocsp_connect_callback(void *context,
	int (*connectcb)(char *host,int port,void *arg),void *arg);

/*
 * enable or disable OSCP verification
 */

extern void tls_client_set_oscp_verification(void *context,int mode);

/*
 * tls_client_add_client_cert
 *
 * add a client certificate and a client key (both files in PEM format)
 * to common connection parameters, tls_getpass is a callback for
 * password input (<prompt> can be abused as a void pointer if
 * required), returns 0 in case of success and -1 in case of an error
 */

extern int tls_client_add_client_cert(void *context,char *cert,char *key,
	int (*tls_getpass)(char *bfr,int size,char *prompt),char *prompt);

/*
 * set the list of ALPN protocols, proto is a pointer array to zero
 * terminated protocol strings of length 1 to 255, returns 0 in case of
 * success and -1 in case of an error
 */

extern int tls_client_set_alpn(void *context,int nproto,char **proto);

/*
 * load emulation template from specified file and appends it to the
 * template chain of the specified template group, the template must
 * match the previously selected emulation or strange hello messages
 * will be created, returns 0 in case of success and -1 in case of error
 */

extern int tls_client_load_hello_template(void *context,int group,char *fn);

/*
 * activates a previously loaded template group for use, a value of -1
 * for the index deactivates any active template, options are a bitwise
 * or of:
 *
 * TLS_CLIENT_EMU_NO_OPTION         - no extra option processing, default
 * TLS_CLIENT_EMU_NO_CERT_BROTLI    - make OpenSSL not append the BROTLI
 *                                    certificate compression extension (1)
 * TLS_CLIENT_EMU_USE_STATIC_GREASE - use grease values incuded in the template
 *				      instead of random grease (2)
 *
 * (1) if the server unexpectedly supports BROTLI certificate compression
 *     one will have to use this flag to be able to connect, though the
 *     use of this option will make the Chromium emulation imperfect
 *
 * (2) if there are grease entries in the template without a value
 *     random grease values are used for these
 */

extern int tls_client_use_hello_template(void *context,int group,int option);

/*
 * returns 1 if the current connection is a resumed connection and 0
 * if it is a new connection
 *
 * WARNING: for mbedTLS this function needs to access internal
 * structures as there is no API to get information about session
 * resumption, so there is NO binary compatability between
 * mbedTLS versions or the same mbedTLS version compiled with
 * different options. Thus one has to explicitely enable this
 * functionality for mbedTLS in the Makefile when compiling the
 * tlsclient library. If not enabled binary compatability for
 * mbedTLS is restored but this function will always return
 * zero for the mbedTLS backend.
 */

extern int tls_client_connection_is_resumed(void *context);

/*
 * returns advisory and estimated remaining resumption data lifetime
 * (based on current time and resumption data recption time) or
 * -1 in case of an error
 */

extern int tls_client_resume_data_lifetime_hint(void *context,void *resume);

/*
 * free resume data returned from tlsclient_disconnect()
 */

extern void tls_client_free_resume_data(void *context,void *resume);

/*
 * tls_client_connect
 *
 * establish a tls connection on top of an existing tcp connection using
 * the specified common connection parameters, <timeout> is the timeout
 * in milliseconds either for connection completion or poll idle time
 * depending on the library used, <host> is the expected host name
 * (used for sni as well as certificate verification) and <verify>
 * is the host name certificate verification flag and optionally
 * try to resume a previous session if <resume> is not NULL - the tcp
 * socket must only be (e)polled after this function is called, it is
 * automatically closed on error return or when tls_client_disconnect
 * is called, returns a pointer to connection data or NULL in case
 * of an error
 */

extern void *tls_client_connect(void *context,int fd,int timeout,char *host,
	int verify,void *resume);

/*
 * tls_client_emulation_connect
 *
 * context    - a context returned by tls_client_emulation_init()
 * timeout    - TLS handshake timeout in milliseconds
 * host       - host name used for SNI and server certificate verification
 * verify     - verify host name of server certificate if 1
 * resume     - session resume data if not NULL
 * tlsver     - on input TLS version of previous session (if resume is
 *		not NULL), on output if not NULL the TLS version of the
 *		established session
 * alpn       - if not NULL points to a location where either NULL or a
 *		pointer to the TLS returned ALPN string is stored
 * tcpconnect - a connect function that either returns a file descriptor
 *		of a tcp connection or -1 in case of an error
 * user       - a pointer to user data for the connect function
 */

extern void *tls_client_emulation_connect(void *context,int timeout,char *host,
	int verify,void *resume,int *tlsver,char **alpn,
	int (*tcpconnect)(void *user),void *user);

/*
 * tls_client_disconnect
 *
 * disconnect and close the established ths session as well as the
 * used tcp socket, must always be called after a successful call
 * to tls_client_connect when the connection is no longer required,
 * it resume is not NULL it points to a location where the address
 * opaque session resume data is stored if available (if not available,
 * NULL is stored).
 */

extern void tls_client_disconnect(void *context,void **resume);

/*
 * returns a pointer (do not free) to the selected ALPN protocol or
 * NULL if no protocol was selected
 */

extern char *tls_client_get_alpn(void *context);

/*
 * returns either the tls version (see definitions above) or -1 if the
 * version could not be retrieved or if it is unknown
 */

extern int tls_client_get_tls_version(void *context);

/*
 * returns the status in case an emulation was used, must be called directly
 * after a tls_client_connect() if the status is required, returns a bitwise
 * or of:
 *
 * TLS_CLIENT_EMU_STATUS_OPTION_ERROR - emu option error (1)
 * TLS_CLIENT_EMU_STATUS_MODIFY_ERROR - emu failed to modify Client Hello
 * TLS_CLIENT_EMU_STATUS_TX_ERROR     - network transmit error happened
 * TLS_CLIENT_EMU_STATUS_RX_ERROR     - network receive error happened
 * TLS_CLIENT_EMU_STATUS_TX_COUNT     - network tx packet count, 15 means >=15
 * TLS_CLIENT_EMU_STATUS_RX_COUNT     - network rx packet count, 15 means >=15
 *
 * (1) currently only used to detect if the server unexpectedly supports
 *     BROTLI certificate compression which OpenSSL 1.1 doesn't handle
 *
 * Note that the data returned is accumulated in a per thread data area
 * during tls_client_connect(), so thread local storage must work, i.e.
 * the __thread keyword must not be a dummy.
 */

extern unsigned int tls_client_get_emulation_error(void);

/*
 * tls_client_write
 *
 * send the specified amount of data over the established tls session,
 * in case of an error -1 is returned and errno is set to either
 * EAGAIN (just (e)poll and retry) or EIO (fatal error), in case of
 * success the amount of bytes sent is returned
 */

extern int tls_client_write(void *context,void *data,int len);

/*
 * tls_client_read
 *
 * read up to the amount specified data from the established tls session,
 * in case of an error -1 is returned and errno is set to either
 * EAGAIN (just (e)poll and retry), EPIPE (connection closed by peer)
 * or EIO (fatal error), in case of success the amount of bytes read
 * is returned
 */

extern int tls_client_read(void *context,void *data,int len);

#endif
