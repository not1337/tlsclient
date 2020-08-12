/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#ifdef HTTP2
#include <nghttp2/nghttp2.h>
#endif
#include "tlsclient.h"

#define ALPNENTRIES	2

#ifdef HTTP2

typedef struct
{
	int32_t id;
	void *tlsctx;
	nghttp2_session *sess;
} H2CTX;

#endif

#ifndef NO_EMU

typedef struct
{
	
	union
	{
		struct sockaddr sa;
		struct sockaddr_in a4;
		struct sockaddr_in6 a6;
	} addr;
	int timeout;
	int fd;
} TCPDATA;

#endif

static const struct
{
	const char *label;
	const char *desc;
	const int emu;
} emulist[]=
{
	{"brave110lx","Brave 1.10.97 Linux",
		TLS_CLIENT_EMULATION_BRAVE_110_LINUX},
	{"brave111a10","Brave 1.11.105 Android 10",
		TLS_CLIENT_EMULATION_BRAVE_111_ANDROID_10},
	{"chrome84a10","Chrome 84.0.4147.111 Android 10",
		TLS_CLIENT_EMULATION_CHROME_84_ANDROID_10},
	{"chromium84lx","Chromium 84.0.4147.89 Linux",
		TLS_CLIENT_EMULATION_CHROMIUM_84_LINUX},
	{"firefox68a10","Firefox 68.11.0 Android 10",
		TLS_CLIENT_EMULATION_FIREFOX_68_ANDROID_10},
	{"firefox78lx","Firefox 78.0.2 Linux",
		TLS_CLIENT_EMULATION_FIREFOX_78_LINUX},
	{"kiwi77a10","Kiwi 77.0.3865.92 Android 10",
		TLS_CLIENT_EMULATION_KIWI_77_ANDROID_10},
	{"konqueror50lx","Konqueror 5.0.97 Linux",
		TLS_CLIENT_EMULATION_KONQUEROR_5_O_LINUX},
	{"opera59a10","Opera 59.1.2926.54067 Android 10",
		TLS_CLIENT_EMULATION_OPERA_59_ANDROID_10},
	{"opera69lx","Opera 69.0.3686.77 Linux",
		TLS_CLIENT_EMULATION_OPERA_69_LINUX},
	{"vivaldi31a10","Vivaldi 3.1.1935.19 Android 10",
		TLS_CLIENT_EMULATION_VIVALDI_31_ANDROID_10},
	{"opera70lx","Opera 70.0.3728.95 Linux",
		TLS_CLIENT_EMULATION_OPERA_70_LINUX},
	{NULL,NULL,-1},
};

static const char *alpn[2]=
{
	"h2",
	"http/1.1"
};

static int passcb(char *buf,int size,char *prompt)
{
	char *bfr;

	if(size<=0)return -1;
	if(!(bfr=getpass(prompt)))return -1;
	strncpy(buf,bfr,size);
	buf[size-1]=0;
	memset(bfr,0,strlen(bfr));
	return strlen(buf);
}

static int gethostaddr(char *host,int port,struct sockaddr *addr)
{
	struct sockaddr_in *a4=(struct sockaddr_in *)addr;
	struct sockaddr_in6 *a6=(struct sockaddr_in6 *)addr;
	struct hostent *hent;
	union
	{
		struct in_addr a4;
		struct in6_addr a6;
	} dst;

	if(inet_pton(AF_INET6,host,&dst.a6)==1)
	{
		memset(addr,0,sizeof(struct sockaddr_in6));
		a6->sin6_family=AF_INET6;
		a6->sin6_addr=dst.a6;
		a6->sin6_port=htons(port);
	}
	else if(inet_pton(AF_INET,host,&dst.a4)==1)
	{
		memset(addr,0,sizeof(struct sockaddr_in));
		a4->sin_family=AF_INET;
		a4->sin_addr=dst.a4;
		a4->sin_port=htons(port);
	}
	else if((hent=gethostbyname2(host,AF_INET6)))
	{
		memset(addr,0,sizeof(struct sockaddr_in6));
		a6->sin6_family=AF_INET6;
		memcpy(&a6->sin6_addr,hent->h_addr,sizeof(dst.a6));
		a6->sin6_port=htons(port);
	}
	else if((hent=gethostbyname2(host,AF_INET)))
	{
		memset(addr,0,sizeof(struct sockaddr_in));
		a4->sin_family=AF_INET;
		memcpy(&a4->sin_addr,hent->h_addr,sizeof(dst.a4));
		a4->sin_port=htons(port);
	}
	else
	{
		fprintf(stderr,"cannot find %s\n",host);
		return -1;
	}

	return 0;
}

static int doconnect(struct sockaddr *addr,int size,int tmo)
{
	int s;
	int l;
	socklen_t sl;
	struct pollfd p;

	if((s=socket(addr->sa_family,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
		0))==-1)
	{
		perror("socket");
		return -1;
	}

	l=1;
	if(setsockopt(s,SOL_TCP,TCP_NODELAY,&l,sizeof(l)))
	{
		perror("setsockopt");
		close(s);
		return -1;
	}

	p.fd=s;
	p.events=POLLOUT;

	if(connect(s,addr,size))
	{
		if(errno==EINPROGRESS)
		{
			switch(poll(&p,1,tmo))
			{
			case -1:perror("poll");
				close(s);
				return -1;
			case 0:	fprintf(stderr,"timeout\n");
				close(s);
				return -1;
			default:if(p.revents&POLLOUT)break;
				fprintf(stderr,"io error\n");
				close(s);
				return -1;
			}

			sl=sizeof(l);
			if(getsockopt(s,SOL_SOCKET,SO_ERROR,&l,&sl))
			{
				perror("getsockopt");
				close(s);
				return -1;
			}
			if(l)
			{
				fprintf(stderr,"io error\n");
				close(s);
				return -1;
			}
		}
		else
		{
			perror("connect");
			close(s);
			return -1;
		}
	}

	return s;
}

static int http11_get(char *host,int fd,void *ctx)
{
	int l;
	struct pollfd p;
	char bfr[1024];

	l=snprintf(bfr,sizeof(bfr),"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",host);

	if(tls_client_write(ctx,bfr,l)!=l)return -1;

	p.fd=fd;
	p.events=POLLIN;

	while(1)
	{
		if(poll(&p,1,5000)<1)return -1;
		if(!(p.revents&POLLIN))return -1;
		if((l=tls_client_read(ctx,bfr,sizeof(bfr)))<0)
		{
			if(errno==EAGAIN)continue;
			else if(errno==EPIPE)return 0;
			else return -1;
		}
	}
}

#ifdef HTTP2

static ssize_t send_callback(nghttp2_session *session,const uint8_t *data,
	size_t length,int flags, void *user_data)
{       
	int len;
	H2CTX *ctx=user_data;

	if((len=tls_client_write(ctx->tlsctx,(void *)data,length))==-1)
	{       
		if(errno==EAGAIN)return NGHTTP2_ERR_WOULDBLOCK;
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return len;
}

static int on_stream_close_callback(nghttp2_session *session,int32_t stream_id,
	uint32_t error_code,void *user_data)
{
	H2CTX *ctx=user_data;

	if(stream_id==ctx->id)
		if(nghttp2_session_terminate_session(session,NGHTTP2_NO_ERROR))
			return NGHTTP2_ERR_CALLBACK_FAILURE;
	return 0;
}

static void hdrset(nghttp2_nv *hdr,char *name,char *value)
{
	hdr->name=(void *)name;
	hdr->value=(void *)value;
	hdr->namelen=strlen(name);
	hdr->valuelen=strlen(value);
	hdr->flags=NGHTTP2_NV_FLAG_NONE;
}

static int http2_get(char *host,int fd,void *ctx)
{
	int r;
	int w;
	int len;
	int pos=0;
	int fill=0;
	int res=0;
	int n=0;
	nghttp2_session *sess;
	nghttp2_session_callbacks *cb;
	H2CTX h2;
	struct pollfd p;
	nghttp2_nv hdrs[4];
	unsigned char bfr[16384];

	memset(&h2,0,sizeof(H2CTX));
	p.fd=fd;
	h2.tlsctx=ctx;

	hdrset(&hdrs[0],":method","GET");
	hdrset(&hdrs[1],":scheme","https");
	hdrset(&hdrs[2],":authority",host);
	hdrset(&hdrs[3],":path","/");

	if(nghttp2_session_callbacks_new(&cb))goto err1;
	nghttp2_session_callbacks_set_send_callback(cb,send_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(cb,
		on_stream_close_callback);
	if(nghttp2_session_client_new(&sess,cb,&h2))
	{
		nghttp2_session_callbacks_del(cb);
		goto err1;
	}
	nghttp2_session_callbacks_del(cb);

	if(nghttp2_submit_settings(sess,NGHTTP2_FLAG_NONE,NULL,0))goto err2;
	if((h2.id=nghttp2_submit_request(sess,NULL,hdrs,4,NULL,&h2))<0)
		goto err2;

	while(1)
	{
repeat:		p.events=0;
		if((r=nghttp2_session_want_read(sess)))p.events|=POLLIN;
		if((w=nghttp2_session_want_write(sess)))p.events|=POLLOUT;
		if(fill)p.events&=~POLLIN;

		if(!r&&!w)break;

		if(poll(&p,1,fill?100:500)<1)
		{
			if(fill)
			{
				len=nghttp2_session_mem_recv(sess,bfr+pos,fill);
				if(len<0)goto err2;
				if(len==fill)n=pos=fill=0;
				else
				{
					pos+=len;
					fill-=len;
				}
				if((n+=100)>=500)goto err2;
				goto repeat;
			}
			else goto err2;
		}
		n=0;

		if(p.revents&(POLLERR|POLLHUP))goto err2;

		if(p.revents&POLLIN)
		{
			fill=tls_client_read(h2.tlsctx,bfr,sizeof(bfr));
			switch(fill)
			{
			case -1:if(errno!=EAGAIN)goto err2;
				fill=0;
			case 0: break;
			default:len=nghttp2_session_mem_recv(sess,bfr,fill);
				if(len<0)goto err2;
				if(len==fill)fill=0;
				else
				{
					pos=len;
					fill-=len;
				}
				break;
			}
		}

		if(p.revents&POLLOUT)
			if(w)if(nghttp2_session_send(sess))goto err2;
	}

	res=0;

err2:	nghttp2_session_del(sess);
err1:	return res;
}

#else

static int http2_get(char *host,int fd,void *ctx)
{
	return -1;
}

#endif

static char *connection_protocol(void *con)
{
	switch(tls_client_get_tls_version(con))
	{
	case TLS_CLIENT_TLS_1_0:
		return "TLSv1.0";
	case TLS_CLIENT_TLS_1_1:
		return "TLSv1.1";
	case TLS_CLIENT_TLS_1_2:
		return "TLSv1.2";
	case TLS_CLIENT_TLS_1_3:
		return "TLSv1.3";
	default:return "unknown protocol";
	}
}

#ifndef NO_EMU

static int tcpcb(void *data)
{
	TCPDATA *tcp=data;

	return (tcp->fd=doconnect(&tcp->addr.sa,sizeof(tcp->addr),
		tcp->timeout));
}

static int emuconnect(char *host,int port,void *cln,int tmo,int verify,
	void *inresume,void **outresume,int dohttp,int *tlsver)
{
	void *con;
	char *proto;
	TCPDATA tcp;

	if(gethostaddr(host,port,&tcp.addr.sa))goto err1;
	tcp.timeout=tmo;

	if(!(con=tls_client_emulation_connect(cln,tmo,host,verify,inresume,
		tlsver,&proto,tcpcb,&tcp)))
	{
		fprintf(stderr,"tls_client_emulation_connect failure\n");
		goto err1;
	}

	if(!proto)proto="http/1.1";

	printf("Connection established using %s and protocol %s.\n",
		connection_protocol(con),proto);
	if(dohttp)
	{
		if(!strcmp(proto,"http/1.1"))printf("%s request %s.\n",proto,
			http11_get(host,tcp.fd,con)?"failed":"ok");
		else if(!strcmp(proto,"h2"))printf("%s request %s.\n",proto,
			http2_get(host,tcp.fd,con)?"failed":"ok");
		else printf("skipping http request with protocol %s\n",proto);
	}
	printf("Disconnecting now.\n");

	tls_client_disconnect(con,outresume);
	return 0;

err1:	return -1;
}

#endif

static int tlsconnect(char *host,int port,void *cln,int tmo,int verify,int emu,
	void *inresume,void **outresume,int dohttp,int *tlsver)
{
	int s;
	void *con;
	char *proto;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in a4;
		struct sockaddr_in6 a6;
	} addr;

	if(emu)if(tls_client_use_hello_template(cln,emu-1,
		TLS_CLIENT_EMU_NO_OPTION))
	{
		fprintf(stderr,"tls_client_use_hello_template failed\n");
		goto err1;
	}

	if(gethostaddr(host,port,&addr.sa))goto err1;

	if((s=doconnect(&addr.sa,sizeof(addr),tmo))==-1)goto err1;

	if(!(con=tls_client_connect(cln,s,tmo,host,verify,inresume)))
	{
		fprintf(stderr,"tls_client_connect failure\n");
		goto err1;
	}

	if(tlsver)*tlsver=tls_client_get_tls_version(con);

	if(!(proto=tls_client_get_alpn(con)))proto="http/1.1";

	printf("Connection established using %s and protocol %s.\n",
		connection_protocol(con),proto);
	if(dohttp)
	{
		if(!strcmp(proto,"http/1.1"))printf("%s request %s.\n",proto,
			http11_get(host,s,con)?"failed":"ok");
		else if(!strcmp(proto,"h2"))printf("%s request %s.\n",proto,
			http2_get(host,s,con)?"failed":"ok");
		else printf("skipping http request with protocol %s\n",proto);
	}
	printf("Disconnecting now.\n");

	tls_client_disconnect(con,outresume);
	return 0;

err1:	return -1;
}

static void usage(char *self)
{
	int i;

	fprintf(stderr,"Usage:\n"
		"%s [<Options>] <hostname>\n"
		"Options:\n"
		"-o            specifically select OpenSSL\n"
		"-m            specifically select mbedTLS\n"
		"-g            specifically select GnuTLS\n"
		"-0            use TLSv1.0 or better (default)\n"
		"-2            use TLSv1.2 or better\n"
		"-3            use TLSv1.3 or better\n"
		"-H            do HTTP GET request when connected\n"
		"-R            test session resumption\n"
		"-c <cafile>   append CA certificates from <cafile>\n"
#ifndef NO_EMU
		"-N <emuname>  emulate named browser (see list below)\n"
		"-l            use loose instead of strict emulation mode\n"
		"-L <path>     path(s) to patched libraries in PATH format\n"
		"-s <emufile>  append template file (development)\n"
		"-E <emu-num>  set the emulation number to use (development)\n"
#endif
		"-A            use ALPN for protocol selection\n"
		"-h            verify hostname against peer certificate\n"
		"-e <certfile> certificate for client authentication\n"
		"-k <keyfile>  key for client authentication\n"
		"-p <port>     connect to <port> (default 443)\n"
		"-t <timeout>  network timeout in milliseconds (default 500)\n"
		"\nIf no ca file is specified the certificate chain is not "
			"verified.\n\n"
		"<emuname>           <desciption>\n",self);
	for(i=0;emulist[i].label;i++)fprintf(stderr,"%-20s%s\n",
		emulist[i].label,emulist[i].desc);
	exit(1);
}

int main(int argc,char *argv[])
{
	int l;
#ifndef NO_EMU
	int tlsver;
#endif
	int r=1;
	int port=443;
	int tmo=500;
	int usealpn=0;
	int verifyhost=0;
	int mode=-1;
	int llemu=0;
	int hlemu=-1;
	int hlmode=TLS_CLIENT_EMULATION_STRICT;
	int lib=TLS_CLIENT_LIBRARY_ANY;
	int scnt=0;
	int cacnt=0;
	int doresume=0;
	int http=0;
	char *ptr;
	void *cln;
	void *rs=NULL;
	char *lpath=NULL;
	char *certfile=NULL;
	char *keyfile=NULL;
	char *sfile[8];
	char *cafile[8];
	char bfr[1024];

#ifndef NO_EMU
	while((l=getopt(argc,argv,"023c:hp:t:e:k:AomgRHs:E:L:lN:"))!=-1)
#else
	while((l=getopt(argc,argv,"023c:hp:t:e:k:AomgRH"))!=-1)
#endif
		switch(l)
	{
	case '0':
		mode=TLS_CLIENT_TLS_1_0;
		break;
	case '2':
		mode=TLS_CLIENT_TLS_1_2;
		break;
	case '3':
		mode=TLS_CLIENT_TLS_1_3;
		break;
	case 'c':
		if(cacnt==8)usage(argv[0]);
		cafile[cacnt++]=optarg;
		break;
	case 'h':
		verifyhost=1;
		break;
	case 'p':
		if((port=atoi(optarg))<1||port>65535)usage(argv[0]);
		break;
	case 't':
		if((tmo=atoi(optarg))<1||tmo>30000)usage(argv[0]);
		break;
	case 'e':
		certfile=optarg;
		break;
	case 'k':
		keyfile=optarg;
		break;
	case 'A':
		usealpn=1;
		break;
	case 's':
		if(scnt==8)usage(argv[0]);
		sfile[scnt++]=optarg;
		break;
	case 'o':
		lib=TLS_CLIENT_LIBRARY_OPENSSL;
		break;
	case 'm':
		lib=TLS_CLIENT_LIBRARY_MBEDTLS;
		break;
	case 'g':
		lib=TLS_CLIENT_LIBRARY_GNUTLS;
		break;
	case 'E':
		if((llemu=atoi(optarg))<1||llemu>65535)usage(argv[0]);
		break;
	case 'N':
		if(hlemu!=-1)usage(argv[0]);
		for(l=0;emulist[l].label;l++)
			if(!strcmp(optarg,emulist[l].label))break;
		if(!emulist[l].label)usage(argv[0]);
		hlemu=emulist[l].emu;
		break;
	case 'l':
		hlmode=TLS_CLIENT_EMULATION_LOOSE;
		break;
	case 'L':
		lpath=optarg;
		break;
	case 'R':
		doresume=1;
		break;
	case 'H':
		http=1;
		break;
	default:usage(argv[0]);
	}

	if((!certfile&&keyfile)||(certfile&&!keyfile))usage(argv[0]);

	if(hlemu!=-1)
	{
		if(llemu||lib!=TLS_CLIENT_LIBRARY_ANY)usage(argv[0]);
		if(mode!=-1||scnt||usealpn)usage(argv[0]);
	}
	else
	{
		if(mode==-1)mode=TLS_CLIENT_TLS_1_0;
		mode|=lib|llemu;
	}

	if(optind!=argc-1)usage(argv[0]);

	if(lpath)
	{
		snprintf(bfr,sizeof(bfr)-16,".:%s",lpath);
		if(!(ptr=getenv("LD_LIBRARY_PATH"))||strcmp(ptr,bfr))
		{
			snprintf(bfr,sizeof(bfr),"LD_LIBRARY_PATH=.:%s",lpath);
			putenv(bfr);
			return execv(argv[0],argv);
		}
	}

	if(tls_client_global_init())
	{
		fprintf(stderr,"tls_client_global_init failed\n");
		goto err1;
	}

	if(hlemu!=-1)
	{
		if(!(cln=tls_client_emulation_init(hlemu,hlmode)))
		{
			fprintf(stderr,"tls_client_emulation_init failed\n");
			goto err2;
		}
	}
	else
	{
		if(!(cln=tls_client_init(mode)))
		{
			fprintf(stderr,"tls_client_init failed\n");
			goto err2;
		}

		if(usealpn)
			if(tls_client_set_alpn(cln,ALPNENTRIES,(char **)alpn))
		{
			fprintf(stderr,"tls_client_set_alpn failed\n");
			goto err3;
		}

		for(l=0;l<scnt;l++)if(tls_client_load_hello_template(cln,
			TLS_CLIENT_EMU_TEMPLATE_GROUP_1,sfile[l]))
		{
			fprintf(stderr,"tls_client_load_hello_template failed "
				"for %s\n",sfile[l]);
			goto err3;
		}
	}

	for(l=0;l<cacnt;l++)if(tls_client_add_cafile(cln,cafile[l]))
	{
		fprintf(stderr,"tls_client_add_cafile failed for %s\n",
			cafile[l]);
		goto err3;
	}

	if(certfile)if(tls_client_add_client_cert(cln,certfile,keyfile,passcb,
		"private key password: "))
	{
		fprintf(stderr,"tls_client_add_client_cert failed\n");
		goto err3;
	}

#ifndef NO_EMU
	if(hlemu!=-1)
	{
		if(!emuconnect(argv[optind],port,cln,tmo,verifyhost,
			NULL,doresume?&rs:NULL,http,&tlsver))r=0;
	}
	else if(!tlsconnect(argv[optind],port,cln,tmo,verifyhost,scnt?1:0,
		NULL,doresume?&rs:NULL,http,NULL))r=0;
#else
	if(!tlsconnect(argv[optind],port,cln,tmo,verifyhost,scnt?1:0,
		NULL,doresume?&rs:NULL,http,NULL))r=0;
#endif

	if(!rs);
#ifndef NO_EMU
	else if(hlemu!=-1)
	{
		r=1;
		if(!emuconnect(argv[optind],port,cln,tmo,verifyhost,rs,NULL,
			http,&tlsver))r=0;
	}
#endif
	else
	{
		r=1;
		if(!tlsconnect(argv[optind],port,cln,tmo,verifyhost,scnt?1:0,
			rs,NULL,http,NULL))r=0;
	}

	if(rs)tls_client_free_resume_data(cln,rs);

err3:	tls_client_fini(cln);
err2:	tls_client_global_fini();
err1:	return r;
}
