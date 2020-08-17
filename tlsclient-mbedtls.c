/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net.h>
#ifdef MBEDTLS_DETECT_RESUME
#include <mbedtls/ssl_internal.h>
#endif
#include "tlsdispatch.h"
#include "tlsclient.h"

typedef struct
{
	COMMON *common;
	COMMON cmn;
	int rng;
	int caflag;
	int major;
	int minor;
	char **alpn;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt crt;
	mbedtls_x509_crt clncrt;
	mbedtls_pk_context pkctx;
} CLIENTCTX;

typedef struct
{
	COMMON *common;
	int isresumed;
	int fd;
	int err;
	time_t stamp;
	mbedtls_ssl_context ssl;
} CONNCTX;

typedef struct
{
	time_t stamp;
	mbedtls_ssl_session sess;
} RESUME;

static inline int isipaddr(char *host)
{
	union
	{
		struct in_addr a4;
		struct in6_addr a6;
	} u;

	if(inet_pton(AF_INET,host,&u)==1)return 1;
	if(inet_pton(AF_INET6,host,&u)==1)return 1;
	return 0;
}

static int tls_random(void *ctx,unsigned char *out,size_t len)
{
	int l;

	if((l=read((int)((long)ctx),out,len))<0)return -9;
	else if(l!=len)return -3;
	else return 0;
}

static int tls_send(void *ctx,const unsigned char *buf,size_t len)
{
	int l;

	if((l=write((int)((long)ctx),buf,len))<0)switch(errno)
	{
	case EWOULDBLOCK:
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	default:return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	else return l;
}

static int tls_recv(void *ctx,unsigned char *buf,size_t len)
{
	int l;

	if((l=read((int)((long)ctx),buf,len))<0)switch(errno)
	{
	case EWOULDBLOCK:
		return MBEDTLS_ERR_SSL_WANT_READ;
	default:return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	else return l;
}

static void tls_debug(void *ctx,int level,const char *file,int line,
	const char *str)
{
}

static int mbed_client_global_init(void)
{
	return 0;
}

static void mbed_client_global_fini(void)
{
}

static void *mbed_client_init(int tls_version,int emu)
{
	CLIENTCTX *ctx;

	if(!(ctx=malloc(sizeof(CLIENTCTX))))goto err1;
	ctx->common=&ctx->cmn;
	ctx->caflag=0;
	ctx->alpn=NULL;
	ctx->major=MBEDTLS_SSL_MAJOR_VERSION_3;
#ifdef MBEDTLS_SSL_MINOR_VERSION_4
	ctx->minor=MBEDTLS_SSL_MINOR_VERSION_4;
#else
	ctx->minor=MBEDTLS_SSL_MINOR_VERSION_3;
#endif
	if((ctx->rng=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)goto err2;
	mbedtls_ssl_config_init(&ctx->conf);
	if(mbedtls_ssl_config_defaults(&ctx->conf,MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT))
			goto err3;
	mbedtls_ssl_conf_authmode(&ctx->conf,MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&ctx->conf,tls_random,(void *)((long)(ctx->rng)));
	mbedtls_ssl_conf_dbg(&ctx->conf,tls_debug,NULL);
	switch(tls_version)
	{
	case TLS_CLIENT_TLS_1_0:
		mbedtls_ssl_conf_min_version(&ctx->conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_1);
		break;
	case TLS_CLIENT_TLS_1_2:
		mbedtls_ssl_conf_min_version(&ctx->conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_3);
		break;
#ifdef MBEDTLS_SSL_MINOR_VERSION_4
	case TLS_CLIENT_TLS_1_3:
		mbedtls_ssl_conf_min_version(&ctx->conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_4);
		break;
#endif
	default:goto err3;
	}
#ifdef MBEDTLS_SSL_MINOR_VERSION_4
	mbedtls_ssl_conf_max_version(&ctx->conf,MBEDTLS_SSL_MAJOR_VERSION_3,
		MBEDTLS_SSL_MINOR_VERSION_4);
#else
	mbedtls_ssl_conf_max_version(&ctx->conf,MBEDTLS_SSL_MAJOR_VERSION_3,
		MBEDTLS_SSL_MINOR_VERSION_3);
#endif
	switch(emu)
	{
	case 0:	break;
	default:goto err3;
	}
	mbedtls_x509_crt_init(&ctx->crt);
	mbedtls_x509_crt_init(&ctx->clncrt);
	mbedtls_pk_init(&ctx->pkctx);
	return ctx;

err3:	mbedtls_ssl_config_free(&ctx->conf);
	close(ctx->rng);
err2:	free(ctx);
err1:	return NULL;
}

static void mbed_client_fini(void *context)
{
	CLIENTCTX *ctx=context;

	mbedtls_pk_free(&ctx->pkctx);
	mbedtls_x509_crt_free(&ctx->clncrt);
	mbedtls_x509_crt_free(&ctx->crt);
	mbedtls_ssl_config_free(&ctx->conf);
	close(ctx->rng);
	if(ctx->alpn)free(ctx->alpn);
	free(ctx);
}

static int mbed_client_add_cafile(void *context,char *fn)
{
	CLIENTCTX *ctx=context;

	if(mbedtls_x509_crt_parse_file(&ctx->crt,fn)<0)return -1;
	ctx->caflag=1;
	return 0;
}

static void mbed_client_set_ocsp_connect_callback(void *context,
	int (*connectcb)(char *host,int port,void *arg),void *arg)
{
}

static void mbed_client_set_oscp_verification(void *context,int mode)
{
}

static int mbed_client_add_client_cert(void *context,char *cert,char *key,
	int (*tls_getpass)(char *bfr,int size,char *prompt),char *prompt)
{
	int r=-1;
	int res;
	CLIENTCTX *ctx=context;
	char pass[512];

	if((res=mbedtls_pk_parse_keyfile(&ctx->pkctx,key,NULL)==
		MBEDTLS_ERR_PK_PASSWORD_REQUIRED))
	{
		if(tls_getpass(pass,sizeof(pass),prompt)<0||!*pass)goto out;
		if(mbedtls_pk_parse_keyfile(&ctx->pkctx,key,pass))goto out;
	}
	else if(res)goto out;
	if(mbedtls_x509_crt_parse_file(&ctx->clncrt,cert)<0)goto out;
	if(mbedtls_ssl_conf_own_cert(&ctx->conf,&ctx->clncrt,&ctx->pkctx))
		goto out;

	r=0;

out:	memset(pass,0,sizeof(pass));
	return r;
}

static int mbed_client_set_alpn(void *context,int nproto,char **proto)
{
	int i;
	int len;
	int l;
	char **alpn;
	char *ptr;
	CLIENTCTX *ctx=context;

	if(ctx->alpn)goto err1;
	for(len=0,i=0;i<nproto;i++)if(!(l=strlen(proto[i]))||len>255)goto err1;
	else len+=l+1+sizeof(char *);
	if(!len)goto err1;
	if(!(alpn=malloc(len+sizeof(char *))))goto err1;
	alpn[nproto]=NULL;
	for(ptr=(char *)&alpn[nproto+1],i=0;i<nproto;i++,ptr+=l)
	{
		alpn[i]=ptr;
		memcpy(ptr,proto[i],(l=strlen(proto[i])+1));
	}
	if(mbedtls_ssl_conf_alpn_protocols(&ctx->conf,(const char **)alpn))
		goto err2;
	ctx->alpn=alpn;
	return 0;

err2:	free(alpn);
err1:	return -1;
}

static void *mbed_client_connect(void *context,int fd,int timeout,char *host,
	int verify,void *resume)
{
	int r;
	uint32_t status;
	CLIENTCTX *cln=context;
	CONNCTX *ctx;
	RESUME *rs=resume;
	struct pollfd p;
	struct timespec now;
#ifndef MBEDTLS_DETECT_RESUME
	const mbedtls_x509_crt *crt;
#endif

	p.fd=fd;
	if(!(ctx=malloc(sizeof(CONNCTX))))goto err1;
	ctx->common=cln->common;
	ctx->isresumed=0;
	ctx->fd=fd;
	ctx->err=0;
	mbedtls_ssl_init(&ctx->ssl);
	if(mbedtls_ssl_setup(&ctx->ssl,&cln->conf))goto err2;
	if(!isipaddr(host))if(mbedtls_ssl_set_hostname(&ctx->ssl,host))
		goto err2;
	if(cln->caflag)mbedtls_ssl_set_hs_ca_chain(&ctx->ssl,&cln->crt,NULL);
	mbedtls_ssl_set_bio(&ctx->ssl,(void *)((long)fd),tls_send,tls_recv,
		NULL);
	if(rs)
	{
		if(mbedtls_ssl_session_reset(&ctx->ssl))goto err2;
		if(mbedtls_ssl_set_session(&ctx->ssl,&rs->sess))goto err2;
	}
	while((r=mbedtls_ssl_handshake(&ctx->ssl)))
	{
#ifdef MBEDTLS_DETECT_RESUME
		/* this absolutely breaks binary compatability though
		   it is the only way the definitely detect if session
		   resume did take place */

		if(ctx->ssl.handshake)if(ctx->ssl.handshake->resume)
			ctx->isresumed=1;
#endif
		switch(r)
		{
		case MBEDTLS_ERR_SSL_WANT_READ:
			p.events=POLLIN;
			if(poll(&p,1,timeout)<1)goto err2;
			if((p.revents&POLLIN)!=POLLIN)goto err2;
			break;
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			p.events=POLLOUT;
			if(poll(&p,1,timeout)<1)goto err2;
			if((p.revents&POLLOUT)!=POLLOUT)goto err2;
			break;
		default:goto err2;
		}
	}
#ifndef MBEDTLS_DETECT_RESUME
	/* this hopefully is a binary compatible way to detect a resumed
	   session - only that it will not work with self signed certificates */

	if((crt=mbedtls_ssl_get_peer_cert(&ctx->ssl)))if(!crt->next)
		ctx->isresumed=1;
#endif
	if(!ctx->isresumed)
	{
		status=mbedtls_ssl_get_verify_result(&ctx->ssl);
		if(status&(MBEDTLS_X509_BADCERT_EXPIRED|
			MBEDTLS_X509_BADCERT_REVOKED|
			MBEDTLS_X509_BADCERT_MISSING|
			MBEDTLS_X509_BADCERT_SKIP_VERIFY|
			MBEDTLS_X509_BADCERT_OTHER|
			MBEDTLS_X509_BADCERT_FUTURE|
			MBEDTLS_X509_BADCERT_BAD_MD|
			MBEDTLS_X509_BADCERT_BAD_PK|
			MBEDTLS_X509_BADCERT_BAD_KEY))goto err2;
		if(verify&&(status&MBEDTLS_X509_BADCERT_CN_MISMATCH))goto err3;
		if(cln->caflag&&(status&MBEDTLS_X509_BADCERT_NOT_TRUSTED))
			goto err3;
	}
	if(clock_gettime(CLOCK_MONOTONIC,&now))goto err3;
	ctx->stamp=now.tv_sec;
	return ctx;

err3:	mbedtls_ssl_close_notify(&ctx->ssl);
err2:	mbedtls_ssl_free(&ctx->ssl);
	free(ctx);
err1:	shutdown(fd,SHUT_RDWR);
	close(fd);
	return NULL;
}

static void mbed_client_disconnect(void *context,void **resume)
{
	CONNCTX *ctx=context;
	RESUME *r;

	if(resume)
	{
		*resume=NULL;
		if((r=malloc(sizeof(RESUME))))
		{
			mbedtls_ssl_session_init(&r->sess);
			r->stamp=ctx->stamp;
			if(mbedtls_ssl_get_session(&ctx->ssl,&r->sess))
				goto fail;
			else if(r->sess.ticket_len)*resume=r;
			else
			{
fail:				mbedtls_ssl_session_free(&r->sess);
				free(r);
			}
		}
	}

	if(!ctx->err)mbedtls_ssl_close_notify(&ctx->ssl);
	mbedtls_ssl_free(&ctx->ssl);
	shutdown(ctx->fd,SHUT_RDWR);
	close(ctx->fd);
	free(ctx);
}

static int mbed_client_connection_is_resumed(void *context)
{
	CONNCTX *ctx=context;

	return ctx->isresumed;
}

static int mbed_client_resume_data_lifetime_hint(void *resume)
{
	RESUME *r=resume;
	struct timespec now;
	time_t passed;

	if(!r)return 0;
	if(clock_gettime(CLOCK_MONOTONIC,&now))return -1;
	passed=now.tv_sec-r->stamp;
	if(r->sess.ticket_lifetime<passed)return 0;
	else return r->sess.ticket_lifetime-passed;
}

static void mbed_client_free_resume_data(void *resume)
{
	RESUME *r=resume;

	if(r)
	{
		mbedtls_ssl_session_free(&r->sess);
		free(r);
	}
}

static char *mbed_client_get_alpn(void *context)
{
	CONNCTX *ctx=context;

	return (char *)mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
}

static int mbed_client_get_tls_version(void *context)
{
	CONNCTX *ctx=context;

	/* breaks binary compatability if used against a mbedTLS library
	   with MBEDTLS_SSL_RENEGOTIATION disabled (usually not the case),
	   breaks binary compatablility if mbedtls_ssl_context without
	   library link time version number change */

	if(ctx->ssl.major_ver!=MBEDTLS_SSL_MAJOR_VERSION_3)return -1;
	switch(ctx->ssl.minor_ver)
	{
	case MBEDTLS_SSL_MINOR_VERSION_1:
		return TLS_CLIENT_TLS_1_0;
	case MBEDTLS_SSL_MINOR_VERSION_2:
		return TLS_CLIENT_TLS_1_1;
	case MBEDTLS_SSL_MINOR_VERSION_3:
		return TLS_CLIENT_TLS_1_2;
#ifdef MBEDTLS_SSL_MINOR_VERSION_4
	case MBEDTLS_SSL_MINOR_VERSION_4:
		return TLS_CLIENT_TLS_1_3;
#endif
	default:return -1;
	}
}

static int mbed_client_write(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	if(!len)return 0;
	if((l=mbedtls_ssl_write(&ctx->ssl,data,len))<0)switch(l)
	{
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		errno=EAGAIN;
		return -1;
	default:errno=EIO;
		ctx->err=1;
		return -1;
	}
	else return l;
}

static int mbed_client_read(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	if(!len)return 0;
	if((l=mbedtls_ssl_read(&ctx->ssl,data,len))<0)switch(l)
	{
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		errno=EAGAIN;
		return -1;
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		ctx->err=1;
		errno=EPIPE;
		return -1;
	default:errno=EIO;
		ctx->err=1;
		return -1;
	}
	else return l;
}

static int mbed_client_get_max_tls_version(void *context)
{
	CLIENTCTX *ctx=context;

	if(ctx->major!=MBEDTLS_SSL_MAJOR_VERSION_3)return -1;
	switch(ctx->minor)
	{
	case MBEDTLS_SSL_MINOR_VERSION_1:
		return TLS_CLIENT_TLS_1_0;
	case MBEDTLS_SSL_MINOR_VERSION_2:
		return TLS_CLIENT_TLS_1_1;
	case MBEDTLS_SSL_MINOR_VERSION_3:
		return TLS_CLIENT_TLS_1_2;
#ifdef MBEDTLS_SSL_MINOR_VERSION_4
	case MBEDTLS_SSL_MINOR_VERSION_4:
		return TLS_CLIENT_TLS_1_3;
#endif
	default:return -1;
	}
}

static int mbed_client_set_max_tls_version(void *context,int version)
{
	CLIENTCTX *ctx=context;

	switch(version)
	{
	case TLS_CLIENT_TLS_1_0:
		mbedtls_ssl_conf_max_version(&ctx->conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_1);
		ctx->minor=MBEDTLS_SSL_MINOR_VERSION_1;
		break;
	case TLS_CLIENT_TLS_1_1:
		mbedtls_ssl_conf_max_version(&ctx->conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_2);
		ctx->minor=MBEDTLS_SSL_MINOR_VERSION_2;
		break;
	case TLS_CLIENT_TLS_1_2:
		mbedtls_ssl_conf_max_version(&ctx->conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_3);
		ctx->minor=MBEDTLS_SSL_MINOR_VERSION_3;
		break;
#ifdef MBEDTLS_SSL_MINOR_VERSION_4
	case TLS_CLIENT_TLS_1_3:
		mbedtls_ssl_conf_max_version(&ctx->conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_4);
		ctx->minor=MBEDTLS_SSL_MINOR_VERSION_4;
		break;
#endif
	default:return -1;
	}
	return 0;
}

WRAPPER mbedtls=
{
	mbed_client_global_init,
	mbed_client_global_fini,
	mbed_client_init,
	mbed_client_fini,
	mbed_client_add_cafile,
	mbed_client_set_ocsp_connect_callback,
	mbed_client_set_oscp_verification,
	mbed_client_add_client_cert,
	mbed_client_set_alpn,
	mbed_client_connect,
	mbed_client_disconnect,
	mbed_client_connection_is_resumed,
	mbed_client_resume_data_lifetime_hint,
	mbed_client_free_resume_data,
	mbed_client_get_alpn,
	mbed_client_get_tls_version,
	mbed_client_write,
	mbed_client_read,
	mbed_client_get_max_tls_version,
	mbed_client_set_max_tls_version,
};
