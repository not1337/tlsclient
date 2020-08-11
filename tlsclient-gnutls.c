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
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include "tlsdispatch.h"
#include "tlsclient.h"

typedef struct
{
	COMMON *common;
	COMMON cmn;
	int caflag;
	int nalpn;
	int sid;
	char *vers;
	gnutls_certificate_credentials_t cred;
	gnutls_datum_t *alpn;
	unsigned char id[32];
} CLIENTCTX;

typedef struct
{
	COMMON *common;
	int fd;
	int err;
	int vryhost;
	int caflag;
	gnutls_session_t sess;
	char alpn[256];
	char host[0];
} CONNCTX;

typedef struct
{
	gnutls_datum_t data;
} RESUME;

#ifndef NO_EMU

static int gnu_pull_timeout_func(gnutls_transport_ptr_t ptr,unsigned int ms)
{
	int tmo=(ms==GNUTLS_INDEFINITE_TIMEOUT?-1:ms);
	struct pollfd p;

	p.fd=(int)((long)ptr);
	p.events=POLLIN;
	switch(poll(&p,1,tmo))
	{
	case -1:return -1;
	case 0:	return 0;
	default:if(p.revents&POLLIN)return 1;
		if(p.revents&(POLLHUP|POLLERR))
		{
			state.rxerr++;
			return -1;
		}
		return 0;
	}
}

static ssize_t gnu_pull_func(gnutls_transport_ptr_t ptr,void *data,size_t len)
{
	ssize_t l;

	if((l=recv((int)((long)ptr),data,len,0))==-1)switch(errno)
	{
	case ENOTCONN:
	case EINTR:
	case EAGAIN:
	case EPROTO:
	case EINPROGRESS:
	case EALREADY:
		break;
	default:state.rxerr++;
		break;
	}
	if(l)state.netrx++;
	return l;
}

static ssize_t gnu_push_func(gnutls_transport_ptr_t ptr,const void *data,
	size_t len)
{
	ssize_t l;
	int extra=0;
	unsigned char *dta;
	struct iovec iov[2];

	if(state.user&TLS_CLIENT_EMU_FF68A10_RETRY)switch(state.step)
	{
	case 1:	dta=(unsigned char *)data;
		if(len>5)if(dta[0]==0x16&&dta[1]==0x03&&dta[5]==0x01)
			state.step++;
		break;

	case 2:	dta=(unsigned char *)data;
		if(len>5)if(dta[0]==0x16&&dta[1]==0x03&&dta[5]==0x01)
		{
			dta[2]=0x03;
			iov[0].iov_base="\x14\x03\x03\x00\x01\x01";
			iov[0].iov_len=extra=6;
			iov[1].iov_base=(void *)data;
			iov[1].iov_len=len;
			state.step++;
		}
		break;

	case 3:	if(len==6&&!memcmp(data,"\x14\x03\x03\x00\x01\x01",6))
		{
			state.step++;
			return 6;
		}
		break;
	}

	if((l=(extra?writev((int)((long)ptr),iov,2):
		send((int)((long)ptr),data,len,0)))==-1)switch(errno)
	{
	case ENOTCONN:
	case EINTR:
	case EAGAIN:
	case EPROTO:
	case EINPROGRESS:
	case EALREADY:
		break;
	default:state.txerr++;
		break;
	}
	else errno=0;
	if(l)state.nettx++;
	return l>=extra?l-extra:0;
}

#endif

static int tls_verify(gnutls_session_t sess)
{
	unsigned int status;
	CONNCTX *ctx;

	ctx=gnutls_session_get_ptr(sess);
	if(gnutls_certificate_verify_peers3(ctx->sess,
		ctx->vryhost?ctx->host:NULL,&status)<0)
			return GNUTLS_E_CERTIFICATE_ERROR;
	if(!status)return 0;
	if(!(status&~(GNUTLS_CERT_INVALID|GNUTLS_CERT_SIGNER_NOT_FOUND))&&
		(status&GNUTLS_CERT_SIGNER_NOT_FOUND)&&!ctx->caflag)return 0;
	if(status==GNUTLS_CERT_UNEXPECTED_OWNER&&!ctx->vryhost)return 0;
	return GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR;
}

static int gnu_client_global_init(void)
{
	return 0;
}

static void gnu_client_global_fini(void)
{
}

static void *gnu_client_init(int tls_version,int emu)
{
	CLIENTCTX *ctx;
	char *vers;

	if(!(ctx=malloc(sizeof(CLIENTCTX))))goto err1;
	ctx->common=&ctx->cmn;
	ctx->sid=0;
	ctx->caflag=0;
	ctx->alpn=NULL;
	switch(tls_version)
	{
	case TLS_CLIENT_TLS_1_0:
		vers="-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-TLS1.1:+VERS-TLS1.2"
			":+VERS-TLS1.3:%COMPAT:%DISABLE_WILDCARDS";
		break;
	case TLS_CLIENT_TLS_1_2:
		vers="-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.3:%COMPAT"
			":%DISABLE_WILDCARDS";
		break;
	case TLS_CLIENT_TLS_1_3:
		vers="-VERS-TLS-ALL:+VERS-TLS1.3:%COMPAT"
			":%DISABLE_WILDCARDS";
		break;
	default:goto err2;
	}
	if(gnutls_certificate_allocate_credentials(&ctx->cred)!=
		GNUTLS_E_SUCCESS)goto err2;
	switch(emu)
	{
	case 0:	if(!(ctx->vers=strdup(vers)))goto err2;
		return ctx;

#ifndef NO_EMU
	case 2:	ctx->sid=1;
		vers="-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-TLS1.1:+VERS-TLS1.2"
			":+VERS-TLS1.3:+3DES-CBC:%DUMBFW:%DISABLE_WILDCARDS";
		if(gnutls_rnd(GNUTLS_RND_NONCE,ctx->id,32))break;
		if(!(ctx->vers=strdup(vers)))goto err2;
		return ctx;
#endif
	}

err2:	free(ctx);
err1:	return NULL;
}

static void gnu_client_fini(void *context)
{
	CLIENTCTX *ctx=context;

	gnutls_certificate_free_credentials(ctx->cred);
	if(ctx->alpn)free(ctx->alpn);
	free(ctx->vers);
	free(ctx);
}

static int gnu_client_add_cafile(void *context,char *fn)
{
	CLIENTCTX *ctx=context;

	if(gnutls_certificate_set_x509_trust_file(ctx->cred,fn,
		GNUTLS_X509_FMT_PEM)<=0)return -1;
	ctx->caflag=1;
	return 0;
}

static int gnu_client_add_client_cert(void *context,char *cert,char *key,
	int (*tls_getpass)(char *bfr,int size,char *prompt),char *prompt)
{
	int r=-1;
	int res;
	CLIENTCTX *ctx=context;
	char pass[512];

	if((res=gnutls_certificate_set_x509_key_file2(ctx->cred,cert,key,
		GNUTLS_X509_FMT_PEM,pass,GNUTLS_PKCS_PLAIN))==
		GNUTLS_E_DECRYPTION_FAILED)
	{
		if(tls_getpass(pass,sizeof(pass),prompt)<0||!*pass)goto out;
		if(gnutls_certificate_set_x509_key_file2(ctx->cred,cert,key,
			GNUTLS_X509_FMT_PEM,pass,0))goto out;
	}
	else if(res)goto out;

	r=0;

out:	memset(pass,0,sizeof(pass));
	return r;
}

static int gnu_client_set_alpn(void *context,int nproto,char **proto)
{
	int len;
	int l;
	int i;
	CLIENTCTX *ctx=context;
	gnutls_datum_t *alpn;
	unsigned char *ptr;

	if(ctx->alpn)goto err1;
	for(len=0,i=0;i<nproto;i++)if(!(l=strlen(proto[i]))||len>255)goto err1;
	else len+=l+1+sizeof(gnutls_datum_t);
	if(!len)goto err1;
	if(!(alpn=malloc(len)))goto err1;
	for(ptr=(unsigned char *)&alpn[nproto],i=0;i<nproto;i++,ptr+=l+1)
	{
		alpn[i].size=l=strlen(proto[i]);
		alpn[i].data=ptr;
		memcpy(ptr,proto[i],l+1);
	}
	ctx->alpn=alpn;
	ctx->nalpn=nproto;
	return 0;

err1:	return -1;
}

static void *gnu_client_connect(void *context,int fd,int timeout,char *host,
	int verify,void *resume)
{
	int r;
	CLIENTCTX *cln=context;
	CONNCTX *ctx;
	RESUME *rs=resume;
	const char *unused;
	gnutls_datum_t sessid;

	if(!(ctx=malloc(sizeof(CONNCTX)+strlen(host)+1)))goto err1;
	ctx->common=cln->common;
	ctx->fd=fd;
	ctx->err=0;
	strcpy(ctx->host,host);
	if(gnutls_init(&ctx->sess,GNUTLS_CLIENT)!=GNUTLS_E_SUCCESS)goto err2;
	if(gnutls_set_default_priority(ctx->sess)!=GNUTLS_E_SUCCESS)goto err3;
	if(gnutls_set_default_priority_append(ctx->sess,cln->vers,&unused,0)!=
		GNUTLS_E_SUCCESS)goto err3;
	if(gnutls_credentials_set(ctx->sess,GNUTLS_CRD_CERTIFICATE,cln->cred)!=
		GNUTLS_E_SUCCESS)goto err3;
	if(gnutls_server_name_set(ctx->sess,GNUTLS_NAME_DNS,ctx->host,
		strlen(ctx->host))!=GNUTLS_E_SUCCESS)goto err3;
	if(cln->alpn)if(gnutls_alpn_set_protocols(ctx->sess,cln->alpn,
		cln->nalpn,0)!=GNUTLS_E_SUCCESS)goto err3;
	if(cln->sid)
	{
		if(gnutls_rnd(GNUTLS_RND_NONCE,cln->id,sizeof(cln->id)))
			goto err3;
		sessid.data=cln->id;
		sessid.size=sizeof(cln->id);
		if(gnutls_session_set_id(ctx->sess,&sessid)!=GNUTLS_E_SUCCESS)
			goto err3;
	}
	if(rs)if(gnutls_session_set_data(ctx->sess,rs->data.data,rs->data.size))
		goto err3;
	/* ugly: to set the verify flags use gnutls_session_set_verify_cert
	   and then instantly override the callback with
	   gnutls_session_set_verify_function - the purpose is to handle
	   the case when the caller on purposes did not provide any CA */
	gnutls_session_set_verify_cert(ctx->sess,NULL,
		GNUTLS_VERIFY_DISABLE_CRL_CHECKS|
		GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS|
		GNUTLS_VERIFY_DO_NOT_ALLOW_IP_MATCHES|
		GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1|
		GNUTLS_VERIFY_IGNORE_UNKNOWN_CRIT_EXTENSIONS|
		(cln->caflag?0:GNUTLS_VERIFY_DISABLE_CA_SIGN));
	gnutls_session_set_verify_function(ctx->sess,tls_verify);
	gnutls_session_set_ptr(ctx->sess,ctx);
	ctx->vryhost=verify;
	ctx->caflag=cln->caflag;
#ifndef NO_EMU
	if(cln->cmn.emuidx!=-1)
	{
		gnutls_transport_set_push_function(ctx->sess,gnu_push_func);
		gnutls_transport_set_pull_function(ctx->sess,gnu_pull_func);
		gnutls_transport_set_pull_timeout_function(ctx->sess,
			gnu_pull_timeout_func);
	}
#endif
	gnutls_transport_set_int(ctx->sess,fd);
	gnutls_handshake_set_timeout(ctx->sess,timeout);
	while((r=gnutls_handshake(ctx->sess))<0)
		if(gnutls_error_is_fatal(r))break;
	if(r<0)goto err3;
	return ctx;

err3:	gnutls_deinit(ctx->sess);
err2:	free(ctx);
err1:	shutdown(fd,SHUT_RDWR);
	close(fd);
	return NULL;
}

static void gnu_client_disconnect(void *context,void **resume)
{
	CONNCTX *ctx=context;
	RESUME *r;

	if(resume)
	{
		*resume=NULL;
		if(gnutls_session_get_flags(ctx->sess)&
			GNUTLS_SFLAGS_SESSION_TICKET)
				if((r=malloc(sizeof(RESUME))))
		{
			if(!gnutls_session_get_data2(ctx->sess,&r->data))
				*resume=r;
			else free(r);
		}
	}

	if(!ctx->err)gnutls_bye(ctx->sess,GNUTLS_SHUT_WR);
	gnutls_deinit(ctx->sess);
	shutdown(ctx->fd,SHUT_RDWR);
	close(ctx->fd);
	free(ctx);
}

static void gnu_client_free_resume_data(void *resume)
{
	RESUME *r=resume;

	if(r)
	{
		gnutls_free(r->data.data);
		free(r);
	}
}

static char *gnu_client_get_alpn(void *context)
{
	CONNCTX *ctx=context;
	gnutls_datum_t alpn;

	if(gnutls_alpn_get_selected_protocol(ctx->sess,&alpn)!=GNUTLS_E_SUCCESS)
		return NULL;
	if(!alpn.size)return NULL;
	memcpy(ctx->alpn,alpn.data,alpn.size);
	ctx->alpn[alpn.size]=0;
	return ctx->alpn;
}

static int gnu_client_get_tls_version(void *context)
{
	CONNCTX *ctx=context;

	switch(gnutls_protocol_get_version(ctx->sess))
	{
	case GNUTLS_TLS1_0:
		return TLS_CLIENT_TLS_1_0;
	case GNUTLS_TLS1_1:
		return TLS_CLIENT_TLS_1_1;
	case GNUTLS_TLS1_2:
		return TLS_CLIENT_TLS_1_2;
	case GNUTLS_TLS1_3:
		return TLS_CLIENT_TLS_1_3;
	default:return -1;
	}
}

static int gnu_client_write(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	if((l=gnutls_record_send(ctx->sess,data,len))<0)switch(l)
	{
	case GNUTLS_E_INTERRUPTED:
	case GNUTLS_E_AGAIN:
		errno=EAGAIN;
		return -1;
	default:errno=EIO;
		return -1;
	}
	else return l;
}

static int gnu_client_read(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	if(!len)return 0;
	if((l=gnutls_record_recv(ctx->sess,data,len))<=0)switch(l)
	{
	case 0:	errno=EPIPE;
		return -1;
	case GNUTLS_E_REHANDSHAKE:
		if(gnutls_alert_send(ctx->sess,GNUTLS_AL_WARNING,
			GNUTLS_A_NO_RENEGOTIATION))
		{
			errno=EIO;
			return -1;
		}
	case GNUTLS_E_INTERRUPTED:
	case GNUTLS_E_AGAIN:
		errno=EAGAIN;
		return -1;
	default:errno=EIO;
		return -1;
	}
	else return l;
}

static int gnu_client_get_max_tls_version(void *context)
{
	int vers=-1;
	CLIENTCTX *ctx=context;
	char *ptr;
	char *mem;
	char bfr[256];

	strcpy(bfr,ctx->vers);
	for(ptr=strtok_r(bfr,":",&mem);ptr;ptr=strtok_r(NULL,":",&mem))
	{
		if(!strcmp(ptr,"+VERS-TLS1.0"))if(vers<0)vers=0;
		if(!strcmp(ptr,"+VERS-TLS1.1"))if(vers<1)vers=1;
		if(!strcmp(ptr,"+VERS-TLS1.2"))if(vers<2)vers=2;
		if(!strcmp(ptr,"+VERS-TLS1.3"))if(vers<3)vers=3;
	}
	switch(vers)
	{
	case 0:	return TLS_CLIENT_TLS_1_0;
	case 1:	return TLS_CLIENT_TLS_1_1;
	case 2:	return TLS_CLIENT_TLS_1_2;
	case 3:	return TLS_CLIENT_TLS_1_3;
	default:return -1;
	}
}

static int gnu_client_set_max_tls_version(void *context,int version)
{
	CLIENTCTX *ctx=context;
	char *ptr;
	char *mem;
	char bfr[256];
	char old[256];

	switch(version)
	{
	case TLS_CLIENT_TLS_1_0:
		strcpy(bfr,"-VERS-TLS-ALL:+VERS-TLS1.0");
		break;
	case TLS_CLIENT_TLS_1_1:
		strcpy(bfr,"-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-TLS1.1");
		break;
	case TLS_CLIENT_TLS_1_2:
		strcpy(bfr,"-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-TLS1.1"
			":+VERS-TLS1.2");
		break;
	case TLS_CLIENT_TLS_1_3:
		strcpy(bfr,"-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-TLS1.1"
			":+VERS-TLS1.2:+VERS-TLS1.3");
		break;
	default:return -1;
	}
	strcpy(old,ctx->vers);
	for(ptr=strtok_r(old,":",&mem);ptr;ptr=strtok_r(NULL,":",&mem))
	{
		if(!strncmp(ptr+1,"VERS-TLS",8))continue;
		strcat(bfr,":");
		strcat(bfr,ptr);
	}
	if(!(ptr=strdup(bfr)))return -1;
	free(ctx->vers);
	ctx->vers=bfr;
	return 0;
}

WRAPPER gnutls=
{
	gnu_client_global_init,
	gnu_client_global_fini,
	gnu_client_init,
	gnu_client_fini,
	gnu_client_add_cafile,
	gnu_client_add_client_cert,
	gnu_client_set_alpn,
	gnu_client_connect,
	gnu_client_disconnect,
	gnu_client_free_resume_data,
	gnu_client_get_alpn,
	gnu_client_get_tls_version,
	gnu_client_write,
	gnu_client_read,
	gnu_client_get_max_tls_version,
	gnu_client_set_max_tls_version,
};
