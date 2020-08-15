/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _TLSDISPATCH_H
#define _TLSDISPATCH_H


#define MAXGROUPS	4

typedef struct chain
{
	struct chain *next;
	void *template;
} CHAIN;

typedef struct
{
	CHAIN *ref;
	uint64_t nettx;
	uint64_t netrx;
	unsigned int rxerr;
	unsigned int txerr;
	unsigned int error;
	unsigned int other;
	unsigned int user;
	unsigned int binder;
	unsigned int step;
} STATE;

typedef struct
{
        int libid;
#ifndef NO_EMU
	int emuidx;
	int emuopt;
	int emumode;
	const void *emulation;
        CHAIN *emu[MAXGROUPS];
#endif
} COMMON;

typedef struct
{
	int (*tls_client_global_init)(void);
	void (*tls_client_global_fini)(void);
	void *(*tls_client_init)(int tls_version,int emu);
	void (*tls_client_fini)(void *context);
	int (*tls_client_add_cafile)(void *context,char *fn);
	void (*tls_client_set_oscp_verification)(void *context,int mode);
	int (*tls_client_add_client_cert)(void *context,char *cert,char *key,
		int (*tls_getpass)(char *bfr,int size,char *prompt),
		char *prompt);
	int (*tls_client_set_alpn)(void *context,int nproto,char **proto);
	void *(*tls_client_connect)(void *context,int fd,int timeout,char *host,
		int verify,void *resume);
	void (*tls_client_disconnect)(void *context,void **resume);
	int (*tls_client_connection_is_resumed)(void *context);
	int (*tls_client_resume_data_lifetime_hint)(void *resume);
	void (*tls_client_free_resume_data)(void *resume);
	char *(*tls_client_get_alpn)(void *context);
	int (*tls_client_get_tls_version)(void *context);
	int (*tls_client_write)(void *context,void *data,int len);
	int (*tls_client_read)(void *context,void *data,int len);
	int (*tls_client_get_max_tls_version)(void *context);
	int (*tls_client_set_max_tls_version)(void *context,int version);
} WRAPPER;

extern __thread STATE state;
extern WRAPPER openssl;
extern WRAPPER mbedtls;
extern WRAPPER gnutls;

#endif
