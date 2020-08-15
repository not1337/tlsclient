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
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include "tlsdispatch.h"
#include "tlsclient.h"

#include <openssl/err.h>

typedef struct
{
	COMMON *common;
	COMMON cmn;
	int caflag;
	int noocsp;
	int (*tls_getpass)(char *bfr,int size,char *prompt);
	char *prompt;
	unsigned char *alpn;
	SSL_CTX *ctx;
} CLIENTCTX;

typedef struct
{
	COMMON *common;
	int fd;
	int err;
	int hint;
	time_t stamp;
	SSL *ssl;
	char alpn[256];
} CONNCTX;

typedef struct
{
	int len;
	int hint;
	time_t stamp;
	unsigned char *ptr;
	unsigned char data[0];
} RESUME;

#ifndef NO_EMU

typedef struct
{ 
	int fd;
} EMUBIO;

static const unsigned char compcert[3]={0x02,0x00,0x02};
static const int groups[3]={NID_X25519,NID_X9_62_prime256v1,NID_secp384r1};
static int methidx=-1;
static BIO_METHOD *biometh;

#endif

static int rngfd=-1;
static int conidx=-1;
static RAND_METHOD sys;

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

#ifndef NO_EMU

static unsigned int dummy_psk_client_cb(SSL *ssl,const char *hint,
	char *identity,unsigned int max_identity_len,unsigned char *psk,
	unsigned int max_psk_len)
{
	return 0;
}

static int add_cb(SSL *s,unsigned int ext_type,unsigned int context,
	const unsigned char **out,size_t *outlen,X509 *x,size_t chainidx,
	int *al,void *add_arg)
{
	switch(ext_type)
	{
	case 0x001b:
		if(state.user&TLS_CLIENT_EMU_NO_CERT_BROTLI)break;
		*out=compcert;
		*outlen=3;
		return 1;
	case 0x7550:
		if(state.user&TLS_CLIENT_EMU_NO_CHANNEL_ID)break;
		*out=(unsigned char *)"";
		*outlen=0;
		return 1;
	case 0x0012:
		*out=NULL;
		*outlen=0;
		return 1;
	}
	return 0;
}

static void free_cb(SSL *s,unsigned int ext_type,unsigned int context,
	const unsigned char *out,void *add_arg)
{
}

static int parse_cb(SSL *s, unsigned int ext_type,unsigned int context,
	const unsigned char *in,size_t inlen, X509 *x,size_t chainidx,int *al,
	void *parse_arg)
{
	switch(ext_type)
	{
	case 0x001b:
	case 0x7550:
		state.other++;
		*al=SSL_R_TLSV1_ALERT_DECODE_ERROR;
		return 0;
	}
	return 1;
}

static int biowrite(BIO *bio,const char *data,int len)
{
	int l;
	EMUBIO *emu=BIO_get_data(bio);

	l=write(emu->fd,data,len);

	BIO_clear_retry_flags(bio);

	if(l<0)switch(errno)
	{
	case ENOTCONN:
	case EINTR:
	case EAGAIN:
	case EPROTO:
	case EINPROGRESS:
	case EALREADY:
		BIO_set_retry_write(bio);
		break;
	default:state.txerr++;
		break;
	}
	else if(l>0)state.nettx++;
	return l;
}

static int biowriteex(BIO *bio,const char *data,size_t len,size_t *processed)
{
	int r;

	if(len>INT_MAX)len=INT_MAX;
	r=biowrite(bio,data,len);
	if(r<0)
	{
		*processed=0;
		return r;
	}
	*processed=r;
	return 1;
}

static int bioread(BIO *bio,char *data,int len)
{
	int l;
	EMUBIO *emu=BIO_get_data(bio);

	l=read(emu->fd,data,len);

	BIO_clear_retry_flags(bio);

	if(l<0)switch(errno)
	{
	case ENOTCONN:
	case EINTR:
	case EAGAIN:
	case EPROTO:
	case EINPROGRESS:
	case EALREADY:
		BIO_set_retry_read(bio);
		break;
	default:state.rxerr++;
		break;
	}
	else if(!l)BIO_set_flags(bio,BIO_FLAGS_IN_EOF);
	else state.netrx++;
	return l;
}

static int bioreadex(BIO *bio, char *data, size_t len,size_t *processed)
{
	int r;

	if(len>INT_MAX)len=INT_MAX;
	r=bioread(bio,data,len);
	if(r<0)
	{
		*processed=0;
		return r;
	}
	*processed=r;
	return 1;
}

static int bioputs(BIO *bio,const char *string)
{
	return biowrite(bio,string,strlen(string));
}

static long bioctrl(BIO *bio,int cmd,long arg,void *parg)
{
	EMUBIO *emu=BIO_get_data(bio);

	switch(cmd)
	{
	case BIO_C_SET_FD:
		if(BIO_get_init(bio))
		{
			if(BIO_get_shutdown(bio))
			{
				close(emu->fd);
			}
			BIO_set_init(bio,0);
		}
		emu->fd=*((int *)parg);
		BIO_set_shutdown(bio,arg?1:0);
		BIO_set_init(bio,1);
		return 1L;

	case BIO_C_GET_FD:
		if(!BIO_get_init(bio))return -1;
		if(parg)*((int *)parg)=emu->fd;
		return (long)(emu->fd);

	case BIO_CTRL_GET_CLOSE:
		return (long)BIO_get_shutdown(bio);

	case BIO_CTRL_SET_CLOSE:
		BIO_set_shutdown(bio,arg?1:0);
		return 1L;

	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		return 1L;

	case BIO_CTRL_EOF:
		return BIO_test_flags(bio,BIO_FLAGS_IN_EOF)?1L:0L;
	}

	return 0L;
}

static int biocreate(BIO *bio)
{
	EMUBIO *emu;

	if(!(emu=malloc(sizeof(EMUBIO))))return 0;
	emu->fd=-1;
	BIO_clear_flags(bio,BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY|
		BIO_FLAGS_BASE64_NO_NL|BIO_FLAGS_MEM_RDONLY|
		BIO_FLAGS_NONCLEAR_RST|BIO_FLAGS_IN_EOF);
	BIO_set_init(bio,0);
	BIO_set_shutdown(bio,0);
	BIO_set_data(bio,emu);
	return 1;
}

static int biodestroy(BIO *bio)
{
	EMUBIO *emu=BIO_get_data(bio);

	if(BIO_get_init(bio))
	{
		if(BIO_get_shutdown(bio))
		{
			close(emu->fd);
		}
	}
	free(emu);
	return 1;
}

#endif

static int getrandom(unsigned char *buf,int num)
{
	return read(rngfd,buf,num);
}

static int ocsp_cb(SSL *s,void *arg)
{
	int i;
	int reason;
	long l;
	const unsigned char *rsp;
	OCSP_RESPONSE *resp;
	OCSP_BASICRESP *basic;
	STACK_OF(X509) *chain;
	X509_STORE *store;
	X509 *x;
	STACK_OF(OPENSSL_STRING) *ulist;
	CLIENTCTX *ctx=arg;
	OCSP_SINGLERESP *single;
	ASN1_GENERALIZEDTIME *revtime;
	ASN1_GENERALIZEDTIME *thisupd;
	ASN1_GENERALIZEDTIME *nextupd;

	ERR_clear_error();

	if(SSL_session_reused(s)||!ctx->caflag||ctx->noocsp)return 1;

	if((l=SSL_get_tlsext_status_ocsp_resp(s,&rsp))==-1)
	{
		if(!rsp)
		{
			/* note, X509_get1_ocsp and X509_email_free are
			   exported but not documented, sigh */
			if(!(x=SSL_get_peer_certificate(s)))goto skip1;
			if(!(ulist=X509_get1_ocsp(x)))goto skip1;
			if(!sk_OPENSSL_STRING_num(ulist))goto skip2;
			/* FIXME: the following function returns the string
			   pointer to the OCSP URL, do stuff here */
			sk_OPENSSL_STRING_value(ulist,0);
			goto skip2;
		}
		else goto err1;
	}
	if(!(resp=d2i_OCSP_RESPONSE(NULL,&rsp,l)))goto err1;

	if(OCSP_response_status(resp)!=OCSP_RESPONSE_STATUS_SUCCESSFUL)
		goto bad2;

	if(!(basic=OCSP_response_get1_basic(resp)))goto err2;
	if(!(chain=SSL_get_peer_cert_chain(s)))goto err3;
	if(!(store=SSL_CTX_get_cert_store(ctx->ctx)))goto err3;

	switch(OCSP_basic_verify(basic,chain,store,0))
	{
	case 0:	goto bad3;
	case -1:goto err3;
	}

	for(i=0;i<OCSP_resp_count(basic);i++)
	{
		if(!(single=OCSP_resp_get0(basic,i)))continue;

		switch(OCSP_single_get0_status(single,&reason,&revtime,
			&thisupd,&nextupd))
		{
		case V_OCSP_CERTSTATUS_GOOD:
			break;
		default:goto bad3;
		case -1:goto err3;
		}

		if(!OCSP_check_validity(thisupd,nextupd,0,-1))goto bad3;
	}

	OCSP_BASICRESP_free(basic);
	OCSP_RESPONSE_free(resp);
	return 1;

err3:	OCSP_BASICRESP_free(basic);
err2:	OCSP_RESPONSE_free(resp);
err1:	return -1;

bad3:	OCSP_BASICRESP_free(basic);
bad2:	OCSP_RESPONSE_free(resp);
	return 0;

skip2:	X509_email_free(ulist);
skip1:	return 1;
}

static int new_session_cb(SSL *s,SSL_SESSION *sess)
{
	CONNCTX *ctx;
	struct timespec now;

	ERR_clear_error();

	if(!(ctx=SSL_get_ex_data(s,conidx)))return 0;
	if(!SSL_SESSION_has_ticket(sess))return 0;
	if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;
	ctx->stamp=now.tv_sec;
	ctx->hint=SSL_SESSION_get_ticket_lifetime_hint(sess);
	return 0;
}

static int password_cb(char *buf,int size,int rwflag,void *u)
{
	CLIENTCTX *ctx=u;

	return ctx->tls_getpass(buf,size,ctx->prompt);
}

static int ssl_client_global_init(void)
{
	if((rngfd=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)goto err1;

	memset(&sys,0,sizeof(sys));
	sys.bytes=getrandom;
	sys.pseudorand=getrandom;
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	if(!RAND_set_rand_method(&sys))goto err2;
	if((conidx=SSL_get_ex_new_index(0,NULL,NULL,NULL,NULL))<0)goto err2;
#ifndef NO_EMU
	if((methidx=BIO_get_new_index())==-1)goto err2;
	if(!(biometh=BIO_meth_new(
		BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR|methidx,
		"socket bio emulation")))goto err2;
	if(!BIO_meth_set_write_ex(biometh,biowriteex))goto err3;
	if(!BIO_meth_set_write(biometh,biowrite))goto err3;
	if(!BIO_meth_set_read_ex(biometh,bioreadex))goto err3;
	if(!BIO_meth_set_read(biometh,bioread))goto err3;
	if(!BIO_meth_set_puts(biometh,bioputs))goto err3;
	if(!BIO_meth_set_ctrl(biometh,bioctrl))goto err3;
	if(!BIO_meth_set_create(biometh,biocreate))goto err3;
	if(!BIO_meth_set_destroy(biometh,biodestroy))goto err3;
#endif
	return 0;

#ifndef NO_EMU
err3:	BIO_meth_free(biometh);
#endif
err2:	close(rngfd);
err1:	return -1;
}

static void ssl_client_global_fini(void)
{
#ifndef NO_EMU
	BIO_meth_free(biometh);
#endif
	close(rngfd);
}

static void *ssl_client_init(int tls_version,int emu)
{
	CLIENTCTX *ctx;

	ERR_clear_error();

	if(!(ctx=malloc(sizeof(CLIENTCTX))))goto err1;
	ctx->common=&ctx->cmn;
	ctx->caflag=0;
	ctx->noocsp=0;
	ctx->alpn=NULL;
	if(!(ctx->ctx=SSL_CTX_new(TLS_client_method())))goto err2;
	switch(tls_version)
	{
	case TLS_CLIENT_TLS_1_0:
		if(!SSL_CTX_set_min_proto_version(ctx->ctx,TLS1_VERSION))
			goto err3;
		break;
	case TLS_CLIENT_TLS_1_2:
		if(!SSL_CTX_set_min_proto_version(ctx->ctx,TLS1_2_VERSION))
			goto err3;
		break;
	case TLS_CLIENT_TLS_1_3:
		if(!SSL_CTX_set_min_proto_version(ctx->ctx,TLS1_3_VERSION))
			goto err3;
		break;
	default:goto err3;
	}
	if(!SSL_CTX_set_max_proto_version(ctx->ctx,TLS1_3_VERSION))goto err3;
	if(!SSL_CTX_set_tlsext_status_type(ctx->ctx,TLSEXT_STATUSTYPE_ocsp))
		goto err3;
	if(!SSL_CTX_set_tlsext_status_cb(ctx->ctx,ocsp_cb))goto err3;
	if(!SSL_CTX_set_tlsext_status_arg(ctx->ctx,ctx))goto err3;
	SSL_CTX_set_verify(ctx->ctx,SSL_VERIFY_NONE,NULL);
	SSL_CTX_set_verify_depth(ctx->ctx,4);
	SSL_CTX_set_options(ctx->ctx,SSL_OP_ALL);
	SSL_CTX_set_options(ctx->ctx,SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_session_cache_mode(ctx->ctx,SSL_SESS_CACHE_CLIENT|
		SSL_SESS_CACHE_NO_INTERNAL);
	SSL_CTX_sess_set_new_cb(ctx->ctx,new_session_cb);
	switch(emu)
	{
	case 0:	return ctx;
#ifndef NO_EMU
	case 1:	SSL_CTX_set_options(ctx->ctx,SSL_OP_NO_ENCRYPT_THEN_MAC);
		if(!SSL_CTX_set_ciphersuites(ctx->ctx,"TLS_AES_128_GCM_SHA256:"
			"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"))
				goto err3;
		if(!SSL_CTX_set_cipher_list(ctx->ctx,
			"ECDHE-ECDSA-AES128-GCM-SHA256:"
			"ECDHE-RSA-AES128-GCM-SHA256:"
			"ECDHE-ECDSA-AES256-GCM-SHA384:"
			"ECDHE-RSA-AES256-GCM-SHA384:"
			"ECDHE-ECDSA-CHACHA20-POLY1305:"
			"ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:"
			"ECDHE-RSA-AES256-SHA:SRP-RSA-AES-256-CBC-SHA:"
			"AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:"
			"AES256-SHA:DES-CBC3-SHA"))goto err3;
		if(!SSL_CTX_set1_groups(ctx->ctx,groups,3))goto err3;
		if(!SSL_CTX_set1_sigalgs_list(ctx->ctx,"ECDSA+SHA256:"
			"RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:"
			"RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:"
			"RSA+SHA512:RSA+SHA1"))goto err3;
		if(!SSL_extension_supported(0x001b))
			if(!SSL_CTX_add_custom_ext(ctx->ctx,0x001b,
				SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS_ONLY,
					add_cb,free_cb,NULL,parse_cb,NULL))
						goto err3;
		if(!SSL_CTX_add_custom_ext(ctx->ctx,0x0012,
			SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS_ONLY,add_cb,free_cb,
			NULL,parse_cb,NULL))goto err3;
		return ctx;

	case 3:	if(!SSL_CTX_set_ciphersuites(ctx->ctx,"TLS_AES_256_GCM_SHA384:"
			"TLS_CHACHA20_POLY1305_SHA256:"
			"TLS_AES_128_GCM_SHA256"
				))goto err3;
		if(!SSL_CTX_set_cipher_list(ctx->ctx,"ALL:-DSS:-AESCCM:-ARIA:"
			"-CAMELLIA:-3DES:-SEED:-IDEA:-RC4:"))goto err3;
		SSL_CTX_set_psk_client_callback(ctx->ctx,dummy_psk_client_cb);
		if(!SSL_extension_supported(0x001b))
			if(!SSL_CTX_add_custom_ext(ctx->ctx,0x001b,
				SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS_ONLY,
					add_cb,free_cb,NULL,parse_cb,NULL))
						goto err3;
		if(!SSL_CTX_add_custom_ext(ctx->ctx,0x0012,
			SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS_ONLY,add_cb,free_cb,
			NULL,parse_cb,NULL))goto err3;
		return ctx;

	case 4:	SSL_CTX_set_options(ctx->ctx,SSL_OP_NO_ENCRYPT_THEN_MAC);
		if(!SSL_CTX_set_ciphersuites(ctx->ctx,"TLS_AES_128_GCM_SHA256:"
			"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"))
				goto err3;
		if(!SSL_CTX_set_cipher_list(ctx->ctx,
			"ECDHE-ECDSA-AES128-GCM-SHA256:"
			"ECDHE-RSA-AES128-GCM-SHA256:"
			"ECDHE-ECDSA-AES256-GCM-SHA384:"
			"ECDHE-RSA-AES256-GCM-SHA384:"
			"ECDHE-ECDSA-CHACHA20-POLY1305:"
			"ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:"
			"ECDHE-RSA-AES256-SHA:SRP-RSA-AES-256-CBC-SHA:"
			"AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:"
			"AES256-SHA:DES-CBC3-SHA"))goto err3;
		if(!SSL_CTX_set1_groups(ctx->ctx,groups,3))goto err3;
		if(!SSL_CTX_set1_sigalgs_list(ctx->ctx,"ECDSA+SHA256:"
			"RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:"
			"RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:"
			"RSA+SHA512:RSA+SHA1"))goto err3;
		if(!SSL_extension_supported(0x7550))
			if(!SSL_CTX_add_custom_ext(ctx->ctx,0x7550,
				SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS_ONLY,
					add_cb,free_cb,NULL,parse_cb,NULL))
						goto err3;
		if(!SSL_CTX_add_custom_ext(ctx->ctx,0x0012,
			SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS_ONLY,add_cb,free_cb,
			NULL,parse_cb,NULL))goto err3;
		return ctx;

		/* in case an emu doesn't need to request OCSP
		   SSL_CTX_set_tlsext_status_type(ctx->ctx,0); */
#endif
	}

err3:	SSL_CTX_free(ctx->ctx);
err2:	free(ctx);
err1:	return NULL;
}

static void ssl_client_fini(void *context)
{
	CLIENTCTX *ctx=context;

	ERR_clear_error();

	SSL_CTX_free(ctx->ctx);
	if(ctx->alpn)free(ctx->alpn);
	free(ctx);
}

static int ssl_client_add_cafile(void *context,char *fn)
{
	CLIENTCTX *ctx=context;

	ERR_clear_error();

	if(!SSL_CTX_load_verify_locations(ctx->ctx,fn,NULL))return -1;
	ctx->caflag=1;
	return 0;
}

static void ssl_client_set_oscp_verification(void *context,int mode)
{
	CLIENTCTX *ctx=context;

	ctx->noocsp=mode;
}

static int ssl_client_add_client_cert(void *context,char *cert,char *key,
	int (*tls_getpass)(char *bfr,int size,char *prompt),char *prompt)
{
	int r=-1;
	CLIENTCTX *ctx=context;
	pem_password_cb *pcb;
	void *u;

	ERR_clear_error();

	pcb=SSL_CTX_get_default_passwd_cb(ctx->ctx);
	u=SSL_CTX_get_default_passwd_cb_userdata(ctx->ctx);
	ctx->tls_getpass=tls_getpass;
	ctx->prompt=prompt;
	SSL_CTX_set_default_passwd_cb(ctx->ctx,password_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx->ctx,ctx);
	if(SSL_CTX_use_certificate_file(ctx->ctx,cert,SSL_FILETYPE_PEM)!=1)
		goto out;
	if(SSL_CTX_use_PrivateKey_file(ctx->ctx,key,SSL_FILETYPE_PEM)!=1)
		goto out;
	r=0;

out:	SSL_CTX_set_default_passwd_cb(ctx->ctx,pcb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx->ctx,u);
	return r;
}

static int ssl_client_set_alpn(void *context,int nproto,char **proto)
{
	int i;
	int len;
	int l;
	unsigned char *alpn;
	unsigned char *ptr;
	CLIENTCTX *ctx=context;

	ERR_clear_error();

	if(ctx->alpn)goto err1;
	for(len=0,i=0;i<nproto;i++)if(!(l=strlen(proto[i]))||l>255)goto err1;
	else len+=l+1;
	if(!len)goto err1;
	if(!(alpn=malloc(len)))goto err1;
	for(ptr=alpn,i=0;i<nproto;i++,ptr+=l)
	{
		*ptr++=(unsigned char)(l=strlen(proto[i]));
		memcpy(ptr,proto[i],l);
	}
	if(SSL_CTX_set_alpn_protos(ctx->ctx,alpn,len))goto err2;
	ctx->alpn=alpn;
	return 0;

err2:	free(alpn);
err1:	return -1;
}

static void *ssl_client_connect(void *context,int fd,int timeout,char *host,
	int verify,void *resume)
{
	int r;
	long status;
	CLIENTCTX *cln=context;
	CONNCTX *ctx;
	RESUME *rs=resume;
	X509 *x509;
#ifndef NO_EMU
	BIO *bio;
#endif
	SSL_SESSION *sess;
	struct pollfd p;

	ERR_clear_error();

	p.fd=fd;
	if(!(ctx=malloc(sizeof(CONNCTX))))goto err1;
	ctx->common=cln->common;
	ctx->fd=fd;
	ctx->err=0;
	ctx->stamp=0;
	ctx->hint=0;
	if(!(ctx->ssl=SSL_new(cln->ctx)))goto err2;
	if(!SSL_set_ex_data(ctx->ssl,conidx,ctx))goto err3;
	if(rs)
	{
		rs->ptr=rs->data;
		if((sess=d2i_SSL_SESSION(NULL,
			(const unsigned char **)(&rs->ptr),rs->len)))
				if(!SSL_set_session(ctx->ssl,sess))
					SSL_SESSION_free(sess);
	}
	SSL_set_hostflags(ctx->ssl,X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if(!SSL_set1_host(ctx->ssl,host))goto err3;
	if(!isipaddr(host))if(!SSL_set_tlsext_host_name(ctx->ssl,host))
		goto err3;
#ifndef NO_EMU
	if(cln->cmn.emuidx!=-1)
	{
		if(!(bio=BIO_new(biometh)))goto err3;
		BIO_set_fd(bio,fd,BIO_NOCLOSE);
		SSL_set_bio(ctx->ssl,bio,bio);
	}
	else if(!SSL_set_fd(ctx->ssl,fd))goto err3;
#else
	if(!SSL_set_fd(ctx->ssl,fd))goto err3;
#endif
	while((r=SSL_connect(ctx->ssl))!=1)
	{
		if(r<0)switch(SSL_get_error(ctx->ssl,r))
		{
		case SSL_ERROR_WANT_READ:
			p.events=POLLIN;
			if(poll(&p,1,timeout)<1)goto err3;
			if((p.revents&POLLIN)!=POLLIN)goto err3;
			break;
		case SSL_ERROR_WANT_WRITE:
			p.events=POLLOUT;
			if(poll(&p,1,timeout)<1)goto err3;
			if((p.revents&POLLOUT)!=POLLOUT)goto err3;
			break;
		default:goto err3;
		}
		else goto err3;
	}

	if(SSL_session_reused(ctx->ssl))return ctx;

	if(!(x509=SSL_get_peer_certificate(ctx->ssl)))goto err4;

	status=SSL_get_verify_result(ctx->ssl);
	switch(status)
	{
	case X509_V_ERR_UNSPECIFIED:
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	case X509_V_ERR_OUT_OF_MEM:
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
	case X509_V_ERR_SUITE_B_INVALID_VERSION:
	case X509_V_ERR_SUITE_B_INVALID_ALGORITHM:
	case X509_V_ERR_SUITE_B_INVALID_CURVE:
	case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
	case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
	case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
	case X509_V_ERR_EE_KEY_TOO_SMALL:
	case X509_V_ERR_CA_KEY_TOO_SMALL:
	case X509_V_ERR_CA_MD_TOO_WEAK:
	case X509_V_ERR_INVALID_CALL:
	case X509_V_ERR_STORE_LOOKUP:
	case X509_V_ERR_NO_VALID_SCTS:
	case X509_V_ERR_OCSP_VERIFY_NEEDED:
	case X509_V_ERR_OCSP_VERIFY_FAILED:
	case X509_V_ERR_OCSP_CERT_UNKNOWN:
		goto err3;
	}

	if(verify)
	{
		if(status==X509_V_ERR_HOSTNAME_MISMATCH)goto err4;
		if(X509_check_host(x509,host,strlen(host),
			X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,NULL)!=1)goto err4;
	}

	if(cln->caflag)switch(status)
	{
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		goto err4;
	}

	return ctx;

err4:	SSL_shutdown(ctx->ssl);
err3:	SSL_free(ctx->ssl);
err2:	free(ctx);
err1:	shutdown(fd,SHUT_RDWR);
	close(fd);
	return NULL;
}

static void ssl_client_disconnect(void *context,void **resume)
{
	CONNCTX *ctx=context;
	SSL_SESSION *sess;
	RESUME *r;
	int len1;
	int len2;

	ERR_clear_error();

	if(resume)
	{
		*resume=NULL;
		if((sess=SSL_get_session(ctx->ssl)))
			if(SSL_SESSION_has_ticket(sess))
				if((len1=i2d_SSL_SESSION(sess,NULL)))
					if((r=malloc(sizeof(RESUME)+len1)))
		{
			r->ptr=r->data;
			len2=i2d_SSL_SESSION(sess,&r->ptr);
			if(len1==len2)
			{
				r->stamp=ctx->stamp;
				r->hint=ctx->hint;
				r->len=len1;
				*resume=r;
			}
			else free(r);
		}
	}

	if(!ctx->err)SSL_shutdown(ctx->ssl);
	SSL_free(ctx->ssl);
	shutdown(ctx->fd,SHUT_RDWR);
	close(ctx->fd);
	free(ctx);
}

static int ssl_client_connection_is_resumed(void *context)
{
	CONNCTX *ctx=context;

	ERR_clear_error();

	return SSL_session_reused(ctx->ssl)?1:0;
}

static int ssl_client_resume_data_lifetime_hint(void *resume)
{
	RESUME *r=resume;
	struct timespec now;
	time_t passed;

	if(!r)return 0;
	if(clock_gettime(CLOCK_MONOTONIC,&now))return -1;
	passed=now.tv_sec-r->stamp;
	if(r->hint<passed)return 0;
	else return r->hint-passed;
}

static void ssl_client_free_resume_data(void *resume)
{
	if(resume)free(resume);
}

static char *ssl_client_get_alpn(void *context)
{
	unsigned int len;
	CONNCTX *ctx=context;
	const unsigned char *data;

	ERR_clear_error();

	SSL_get0_alpn_selected(ctx->ssl,&data,&len);
	if(!data)return NULL;
	memcpy(ctx->alpn,data,len);
	ctx->alpn[len]=0;
	return ctx->alpn;
}

static int ssl_client_get_tls_version(void *context)
{
	CONNCTX *ctx=context;

	ERR_clear_error();

	switch(SSL_version(ctx->ssl))
	{
	case TLS1_VERSION:
		return TLS_CLIENT_TLS_1_0;
	case TLS1_1_VERSION:
		return TLS_CLIENT_TLS_1_1;
	case TLS1_2_VERSION:
		return TLS_CLIENT_TLS_1_2;
	case TLS1_3_VERSION:
		return TLS_CLIENT_TLS_1_3;
	default:return -1;
	}
}

static int ssl_client_write(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	ERR_clear_error();

	if(!len)return 0;
	if((l=SSL_write(ctx->ssl,data,len))<=0)switch(SSL_get_error(ctx->ssl,l))
	{
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno=EAGAIN;
		return -1;
	default:errno=EIO;
		ctx->err=1;
		return -1;
	}
	else return l;
}

static int ssl_client_read(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	ERR_clear_error();

	if(!len)return 0;
	if((l=SSL_read(ctx->ssl,data,len))<=0)switch(SSL_get_error(ctx->ssl,l))
	{
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno=EAGAIN;
		return -1;
	case SSL_ERROR_ZERO_RETURN:
		errno=EPIPE;
		ctx->err=1;
		return -1;
	default:errno=EIO;
		ctx->err=1;
		return -1;
	}
	else return l;
}

static int ssl_client_get_max_tls_version(void *context)
{
	CLIENTCTX *ctx=context;

	ERR_clear_error();

	switch(SSL_CTX_get_max_proto_version(ctx->ctx))
	{
	case TLS1_VERSION:
		return TLS_CLIENT_TLS_1_0;
	case TLS1_1_VERSION:
		return TLS_CLIENT_TLS_1_1;
	case TLS1_2_VERSION:
		return TLS_CLIENT_TLS_1_2;
	case TLS1_3_VERSION:
		return TLS_CLIENT_TLS_1_3;
	default:return -1;
	}
}

static int ssl_client_set_max_tls_version(void *context,int version)
{
	CLIENTCTX *ctx=context;

	ERR_clear_error();

	switch(version)
	{
	case TLS_CLIENT_TLS_1_0:
		return SSL_CTX_set_max_proto_version(ctx->ctx,TLS1_VERSION)?
			0:-1;
	case TLS_CLIENT_TLS_1_1:
		return SSL_CTX_set_max_proto_version(ctx->ctx,TLS1_1_VERSION)?
			0:-1;
	case TLS_CLIENT_TLS_1_2:
		return SSL_CTX_set_max_proto_version(ctx->ctx,TLS1_2_VERSION)?
			0:-1;
	case TLS_CLIENT_TLS_1_3:
		return SSL_CTX_set_max_proto_version(ctx->ctx,TLS1_3_VERSION)?
			0:-1;
	default:return -1;
	}
}

WRAPPER openssl=
{
	ssl_client_global_init,
	ssl_client_global_fini,
	ssl_client_init,
	ssl_client_fini,
	ssl_client_add_cafile,
	ssl_client_set_oscp_verification,
	ssl_client_add_client_cert,
	ssl_client_set_alpn,
	ssl_client_connect,
	ssl_client_disconnect,
	ssl_client_connection_is_resumed,
	ssl_client_resume_data_lifetime_hint,
	ssl_client_free_resume_data,
	ssl_client_get_alpn,
	ssl_client_get_tls_version,
	ssl_client_write,
	ssl_client_read,
	ssl_client_get_max_tls_version,
	ssl_client_set_max_tls_version,
};
