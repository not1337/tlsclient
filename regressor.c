/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#define _GNU_SOURCE
#include <pthread.h>
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
#include <nghttp2/nghttp2.h>
#include "clientdata.h"
#include "clientdissect.h"
#include "clientdump.h"
#include "tlsclient.h"

#define MAXENTRIES 9

/*
 * "broken server" means that the server just closes the connection
 * after receiving the client hello message every time the client connects
 */

typedef struct
{
	/* initial connect to TLSv1.2 server */
	const char *noresume12[MAXENTRIES];
	/* initial connect to TLSv1.3 server */
	const char *noresume13[MAXENTRIES];
	/* resuming connect to TLSv1.2 server */
	const char *resume12[MAXENTRIES];
	/* resuming connect to TLSv1.3 server */
	const char *resume13[MAXENTRIES];
	/* initial connect to broken server */
	const char *discno[MAXENTRIES];
	/* TLSv1.2 resuming connect to broken server */
	const char *disc12[MAXENTRIES];
	/* TLSv1.3 resuming connect to broken server */
	const char *disc13[MAXENTRIES];
	/* resuming TLSv1.2, broken server disconnects n times, then accepts */
	const int ndisc12;
	const char *discres12[MAXENTRIES];
	/* resuming TLSv1.3, broken server disconnects n times, then accepts */
	const int ndisc13;
	const char *discres13[MAXENTRIES];
} SEQUENCE;

#include "regression/brave_1_10_linux.h"
#include "regression/brave_1_11_android_10.h"
#include "regression/chrome_84_android_10.h"
#include "regression/chromium_84_linux.h"
#include "regression/firefox_68_android_10.h"
#include "regression/firefox_78_linux.h"
#include "regression/kiwi_77_android_10.h"
#include "regression/konqueror_5_0_linux.h"
#include "regression/opera_59_android_10.h"
#include "regression/opera_69_linux.h"
#include "regression/vivaldi_3_1_android_10.h"
#include "regression/opera_70_linux.h"
#include "regression/firefox_79_android_10.h"
#include "regression/brave_1_12_android_10.h"
#include "regression/vivaldi_3_2_android_10.h"
#include "regression/chromium_85_linux.h"

#define BUFSIZE		65536

typedef struct
{
	int32_t id;
	void *tlsctx;
	nghttp2_session *sess;
} H2CTX;

typedef struct hellodata
{
	struct hellodata *next;
	int size;
	unsigned char data[0];
} HELLODATA;

typedef struct
{
	union
	{
		struct sockaddr sa;
		struct sockaddr_in a4;
		struct sockaddr_in6 a6;
	} addr;
	int nettimeout;
	int tlstimeout;
	int tothello;
	void *context;
	char host[256];

	void (*collector)(unsigned char *data,int len,void *user);
	int state;
	HELLODATA *data;

	pthread_t thread;
	int numhello;
	int running;
	int doesfail;
	int failcnt;
	int fd;
	int lcl;
	int rmt;
} JOB;

static const struct
{
	const SEQUENCE *seq;
	const char *name;
	const int emu;
} regress[]=
{
	{&brave_1_10_linux,"Brave 1.10.97 Linux",
		TLS_CLIENT_EMULATION_BRAVE_110_LINUX},
	{&brave_1_11_android_10,"Brave 1.11.105 Android 10",
		TLS_CLIENT_EMULATION_BRAVE_111_ANDROID_10},
	{&brave_1_12_android_10,"Brave 1.12.113 Android 10",
		TLS_CLIENT_EMULATION_BRAVE_112_ANDROID_10},
	{&chrome_84_android_10,"Chrome 84.0.4147.111 Android 10",
		TLS_CLIENT_EMULATION_CHROME_84_ANDROID_10},
	{&chromium_84_linux,"Chromium 84.0.4147.89 Linux",
		TLS_CLIENT_EMULATION_CHROMIUM_84_LINUX},
	{&chromium_85_linux,"Chromium 85.0.4183.83 Linux",
		TLS_CLIENT_EMULATION_CHROMIUM_85_LINUX},
	{&firefox_68_android_10,"Firefox 68.11.0 Android 10",
		TLS_CLIENT_EMULATION_FIREFOX_68_ANDROID_10},
	{&firefox_78_linux,"Firefox 78.0.2 Linux",
		TLS_CLIENT_EMULATION_FIREFOX_78_LINUX},
	{&firefox_79_android_10,"Firefox 79.0.5 Android 10",
		TLS_CLIENT_EMULATION_FIREFOX_79_ANDROID_10},
	{&kiwi_77_android_10,"Kiwi 77.0.3865.92 Android 10",
		TLS_CLIENT_EMULATION_KIWI_77_ANDROID_10},
	{&konqueror_5_0_linux,"Konqueror 5.0.97 Linux",
		TLS_CLIENT_EMULATION_KONQUEROR_5_O_LINUX},
	{&opera_59_android_10,"Opera 59.1.2926.54067 Android 10",
		TLS_CLIENT_EMULATION_OPERA_59_ANDROID_10},
	{&opera_69_linux,"Opera 69.0.3686.77 Linux",
		TLS_CLIENT_EMULATION_OPERA_69_LINUX},
	{&opera_70_linux,"Opera 70.0.3728.95 Linux",
		TLS_CLIENT_EMULATION_OPERA_70_LINUX},
	{&vivaldi_3_1_android_10,"Vivaldi 3.1.1935.19 Android 10",
		TLS_CLIENT_EMULATION_VIVALDI_31_ANDROID_10},
	{&vivaldi_3_2_android_10,"Vivaldi 3.2.1996.26 Android 10",
		TLS_CLIENT_EMULATION_VIVALDI_32_ANDROID_10},
	{NULL,NULL,0},
};

static struct
{
	int idx;
	int bits;
	char *name;
	char *desc;
}tests[]=
{
	{0,1,"std12","TLSv1.2 no resume, then resume"},
	{1,2,"std13","TLSv1.3 no resume, then resume"},
	{2,3,"inifail","no resume, fully broken server not answering to Hello"},
	{3,1,"v12fail","TLSv1.2 resume to fully broken not answering server"},
	{4,2,"v13fail","TLSv1.3 resume to fully broken not answering server"},
	{5,1,"v12int","TLSv1.2 resume to temporarily broken server"},
	{6,2,"v13int","TLSv1.3 resume to temporarily broken server"},
	{-1,-1,NULL,NULL},
};

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

static void tcpforward(int lcl,int rmt,
	void (*collector)(unsigned char *data,int len,void *user),void *user)
{
	int len;
	int lrfill;
	int rlfill;
	int lev;
	int rev;
	int state;
	struct pollfd p[2];
	char lclrmt[BUFSIZE];
	char rmtlcl[BUFSIZE];
	char oob;

	p[0].fd=lcl;
	p[1].fd=rmt;

	state=0x0000;
	lev=POLLIN|POLLPRI|POLLRDHUP;
	rev=POLLIN|POLLPRI|POLLRDHUP;
	lrfill=0;
	rlfill=0;

	while(lev||rev)
	{
		p[0].events=lev;
		p[1].events=rev;

		switch(poll(p,2,-1))
		{
		case -1:continue;
		case 0:	shutdown(lcl,SHUT_RDWR);
			shutdown(rmt,SHUT_RDWR);
			return;
		}

		if(p[0].revents&POLLRDHUP)state|=0x0010;

		if(p[0].revents&(POLLERR|POLLHUP|POLLNVAL))state|=0x0004;

		if(p[0].revents&POLLPRI)switch(recv(lcl,&oob,1,MSG_OOB))
		{
		case 0:
		case -1:state|=0x0001;
			break;

		default:if(send(rmt,&oob,1,MSG_OOB)!=1)state|=0x0008;
			break;
		}

		if(p[0].revents&POLLIN)
		{
			if((len=read(lcl,lclrmt+lrfill,BUFSIZE-lrfill))<=0)
			{
				if(!len&&(state&0x0010))state|=0x0040;
				state|=0x0001;
			}
			else
			{
				if(collector)collector((unsigned char *)
					(lclrmt+lrfill),len,user);
				lrfill+=len;
			}

			if((state&0x0050)==0x0050)shutdown(rmt,SHUT_WR);
		}

		if(p[1].revents&POLLRDHUP)state|=0x0020;

		if(p[1].revents&(POLLERR|POLLHUP|POLLNVAL))state|=0x0008;

		if(p[1].revents&POLLPRI)switch(recv(rmt,&oob,1,MSG_OOB))
		{
		case 0:
		case -1:state|=0x0002;
			break;

		default:if(send(lcl,&oob,1,MSG_OOB)!=1)state|=0x0004;
			break;
		}

		if(p[1].revents&POLLIN)
		{
			if((len=read(rmt,rmtlcl+rlfill,BUFSIZE-rlfill))<=0)
			{
				if(!len&&(state&0x0020))state|=0x0080;
				state|=0x0002;
			}
			else rlfill+=len;

			if((state&0x00a0)==0x00a0)shutdown(lcl,SHUT_WR);
		}

		if(lrfill&&!(state&0x0008))
		{
			if((len=write(rmt,lclrmt,lrfill))>=0)
			{
				lrfill-=len;
				if(len)memmove(lclrmt,lclrmt+len,lrfill);
			}
			else
			{
				if(errno!=EAGAIN&&errno!=EWOULDBLOCK)
					state|=0x0008;
				else if((p[1].events&POLLOUT)&&
					(p[1].revents&POLLOUT))state|=0x0008;
			}
		}

		if(rlfill&&!(state&0x0004))
		{
			if((len=write(lcl,rmtlcl,rlfill))>=0)
			{
				rlfill-=len;
				if(len)memmove(rmtlcl,rmtlcl+len,rlfill);
			}
			else
			{
				if(errno!=EAGAIN&&errno!=EWOULDBLOCK)
					state|=0x0004;
				else if((p[0].events&POLLOUT)&&
					(p[0].revents&POLLOUT))state|=0x0004;
			}
		}

		if((state&0x0009)||lrfill==BUFSIZE)lev=0;
		else lev=POLLIN|POLLPRI|POLLRDHUP;
		if(!(state&0x0004)&&rlfill)lev|=POLLOUT;

		if((state&0x0006)||rlfill==BUFSIZE)rev=0;
		else rev=POLLIN|POLLPRI|POLLRDHUP;
		if(!(state&0x0008)&&lrfill)rev|=POLLOUT;
	}
}

static int read_hello(int fd,unsigned char *bfr,int size)
{
	int len=0;
	int tot;
	int l;
	struct pollfd p;

	if(size<5)return -1;
	p.fd=fd;
	p.events=POLLIN;

	while(len<5)
	{
		if(poll(&p,1,500)!=1||!(p.revents&POLLIN))return -1;
		if((l=read(fd,bfr+len,5-len))<=0)return -1;
		len+=l;
	}
	tot=bfr[3];
	tot<<=8;
	tot+=bfr[4];
	tot+=5;
	if(size<tot)return -1;
	while(len<tot)
	{
		if(poll(&p,1,500)!=1||!(p.revents&POLLIN))return -1;
		if((l=read(fd,bfr+len,tot-len))<=0)return -1;
		len+=l;
	}
	return len;
}

static void *networker(void *param)
{
	JOB *job=param;

	job->running=1;
	tcpforward(job->lcl,job->rmt,job->collector,job);
	close(job->rmt);
	close(job->lcl);
	pthread_exit(NULL);
}

static void *dummyworker(void *param)
{
	int len;
	JOB *job=param;
	HELLODATA **data;
	unsigned char bfr[1024];

	job->running=1;
	if((len=read_hello(job->lcl,bfr,sizeof(bfr)))!=-1)
	{
		for(data=&job->data;*data;data=&(*data)->next);
		if((*data=malloc(sizeof(HELLODATA)+len)))
		{
			(*data)->next=NULL;
			(*data)->size=len;
			memcpy((*data)->data,bfr,len);
		}
	}
	close(job->lcl);
	pthread_exit(NULL);
}

static void hellocollect(unsigned char *data,int len,void *user)
{
	JOB *job=user;
	int offset=0;
	HELLODATA **dta;

	if(len>=6)if(!memcmp(data,"\x14\x03\x01\x00\x01\x01",6)||
		!memcmp(data,"\x14\x03\x03\x00\x01\x01",6))offset=6;
	if(len>=offset+6)if(!memcmp(data+offset,"\x16\x03\x01",3)||
		!memcmp(data+offset,"\x16\x03\x03",3))
			if(data[offset+5]==0x01)
	{
		if(++(job->numhello)==job->tothello)job->collector=NULL;
		for(dta=&job->data;*dta;dta=&(*dta)->next);
		if((*dta=malloc(sizeof(HELLODATA)+len)))
		{
			(*dta)->next=NULL;
			(*dta)->size=len;
			memcpy((*dta)->data,data,len);
		}
	}
}

static int netconnect(void *user)
{
	JOB *job=user;
	int pair[2];

	if((job->rmt=doconnect(&job->addr.sa,sizeof(job->addr),job->nettimeout))
		==-1)return -1;
	if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair))
	{
		close(job->rmt);
		return -1;
	}
	job->fd=pair[0];
	job->lcl=pair[1];
	job->collector=hellocollect;
	if(pthread_create(&job->thread,NULL,networker,job))
	{
		close(job->rmt);
		close(job->lcl);
		close(job->fd);
		return -1;
	}
	return job->fd;
}

static int dummyconnect(void *user)
{
	JOB *job=user;
	int pair[2];

	if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair))
		return -1;
	job->fd=pair[0];
	job->lcl=pair[1];
	if(pthread_create(&job->thread,NULL,dummyworker,job))
	{
		close(job->lcl);
		close(job->fd);
		return -1;
	}
	return job->fd;
}

static int multiconnect(void *user)
{
	JOB *job=user;

	if(job->failcnt)
	{
		job->failcnt--;
		return dummyconnect(user);
	}
	return netconnect(user);
}

static int runner(JOB *job,int mode,void *inresume,void **outresume,int *tlsver)
{
	char *proto;
	void *con;
	static int (*connector)(void *user);

	job->running=0;
	job->state=0;
	job->numhello=0;
	job->data=NULL;

	switch(mode)
	{
	case 0:	connector=dummyconnect;
		break;
	case 1:	connector=netconnect;
		break;
	case 2:	connector=multiconnect;
		break;
	default:return -1;
	}

	if(!(con=tls_client_emulation_connect(job->context,job->tlstimeout,
		job->host,0,inresume,tlsver,&proto,connector,job)))
	{
		if(job->running)pthread_join(job->thread,NULL);
		return -1;
	}

	job->state=1;

	if(!proto)proto="http/1.1";
	else job->state|=2;

	if(!strcmp(proto,"http/1.1"))
	{
		job->state|=4;
		if(!http11_get(job->host,job->fd,con))job->state|=8;
	}
	else if(!strcmp(proto,"h2"))
	{
		job->state|=4;
		if(!http2_get(job->host,job->fd,con))job->state|=8;
	}

	tls_client_disconnect(con,outresume);
	return 0;
}

static int prepare_job(JOB *job,char *host,int port,int timeout)
{
	if(strlen(host)>=sizeof(job->host))return -1;
	memset(job,0,sizeof(JOB));
	strcpy(job->host,host);
	if(gethostaddr(host,port,&job->addr.sa))return -1;
	job->nettimeout=timeout;
	return 0;
}

static int str2hex(const char *in,unsigned char *out)
{
	if(in[0]>='0'&&in[0]<='9')*out=in[0]-'0';
	else if(in[0]>='A'&&in[0]<='F')*out=in[0]-'A'+10;
	else if(in[0]>='a'&&in[0]<='f')*out=in[0]-'a'+10;
	else return -1;
	*out<<=4;
	if(in[1]>='0'&&in[1]<='9')*out|=in[1]-'0';
	else if(in[1]>='A'&&in[1]<='F')*out|=in[1]-'A'+10;
	else if(in[1]>='a'&&in[1]<='f')*out|=in[1]-'a'+10;
	else return -1;
	return 0;
}

static int comparator(const char * const *seq,HELLODATA *data)
{
	int i;
	int j;
	int r;
	int len;
	int dpre;
	int rpre;
	CLIENTHELLO *left;
	CLIENTHELLO *right;
	unsigned char bfr[1024];

	for(i=0;seq[i];i++,data=data->next)
	{
		if(!data)
		{
			printf("missing emulation hello packet %d\n",i+1);
			return -1;
		}

		for(j=0,len=0;seq[i][j]&&len<sizeof(bfr);len++,j+=2)
			if(str2hex(&seq[i][j],&bfr[len]))
		{
			printf("reference data read error packet %d\n",i+1);
			return -1;
		}

		dpre=0;
		if(data->size>=6)
			if(!memcmp(data->data,"\x14\x03\x01\x00\x01\x01",6)||
			   !memcmp(data->data,"\x14\x03\x03\x00\x01\x01",6))
				dpre=1;

		rpre=0;
		if(len>=6)if(!memcmp(bfr,"\x14\x03\x01\x00\x01\x01",6)||
			!memcmp(bfr,"\x14\x03\x03\x00\x01\x01",6))
				rpre=1;

		if(dpre!=rpre)
		{
			if(!dpre)printf("missing Change Cipher Spec packet "
				"%d\n",i+1);
			else printf("surplus Change Cipher Spec packet %d\n",
				i+1);
		}
		else if(dpre)if(memcmp(data->data,bfr,6))
			printf("differing Change Cipher Spec packet %d\n",i+1);

		if(!(left=dissect_clienthello(bfr,len,1,0,0)))
		{
			printf("reference data error packet %d\n",i+1);
			return -1;
		}

		if(!(right=dissect_clienthello(data->data,data->size,1,0,0)))
		{
			printf("emulation hello message bad packet %d\n",i+1);
			free_clienthello(left);
			return -1;
		}

		if((r=diff_clienthello(left,right,0,1))<0)
		{
			printf("internal error packet %d\n",i+1);
			return -1;
		}

		if(r)printf("(packet %d)\n\n",i+1);

		free_clienthello(left);
		free_clienthello(right);
	}

	if(data)
	{
		printf("surplus emulation hello packet %d\n",i+1);
		return -1;
	}

	return 0;
}

static int run_test(JOB *job,int idx,int which,int timeout)
{
	int res=-1;
	int tlsver;
	int mode;
	int altfail;
	int altmode;
	int failcnt;
	void *resume=NULL;
	HELLODATA *e;
	const char * const *seq1;
	const char * const *seq2;

	job->tlstimeout=timeout;

	switch(which)
	{
	case 0:	seq1=regress[idx].seq->noresume12;
		seq2=regress[idx].seq->resume12;
		job->doesfail=0;
		altfail=0;
		mode=1;
		altmode=1;
		failcnt=0;
		break;
	case 1:	seq1=regress[idx].seq->noresume13;
		seq2=regress[idx].seq->resume13;
		job->doesfail=0;
		altfail=0;
		mode=1;
		altmode=1;
		failcnt=0;
		break;
	case 2:	seq1=regress[idx].seq->discno;
		seq2=NULL;
		job->doesfail=1;
		altfail=0;
		mode=0;
		altmode=0;
		failcnt=0;
		break;
	case 3:	seq1=regress[idx].seq->noresume12;
		seq2=regress[idx].seq->disc12;
		job->doesfail=0;
		altfail=1;
		mode=1;
		altmode=0;
		failcnt=0;
		break;
	case 4:	seq1=regress[idx].seq->noresume13;
		seq2=regress[idx].seq->disc13;
		job->doesfail=0;
		altfail=1;
		mode=1;
		altmode=0;
		failcnt=0;
		break;
	case 5:	seq1=regress[idx].seq->noresume12;
		seq2=regress[idx].seq->discres12;
		job->doesfail=0;
		altfail=0;
		mode=1;
		altmode=2;
		if(!(failcnt=regress[idx].seq->ndisc12))return 0;
		break;
	case 6:	seq1=regress[idx].seq->noresume13;
		seq2=regress[idx].seq->discres13;
		job->doesfail=0;
		altfail=0;
		mode=1;
		altmode=2;
		if(!(failcnt=regress[idx].seq->ndisc13))return 0;
		break;
	default:printf("internal error\n");
		goto err1;
	}

	printf("%s\n",regress[idx].name);

	job->failcnt=0;

	if(!(job->context=tls_client_emulation_init(regress[idx].emu,
		TLS_CLIENT_EMULATION_STRICT)))
	{
		printf("tls_client_emulation_init failure\n");
		goto err1;
	}

	for(job->tothello=0;seq1[job->tothello];job->tothello++);

	if(runner(job,mode,NULL,seq2?&resume:NULL,&tlsver))
	{
		if(!job->doesfail)
		{
			printf("emulation run failed\n");
			goto err2;
		}
	}
	else if(job->doesfail)
	{
		printf("emulation unexpectedly succeeded\n");
		goto err3;
	}

	if(!job->doesfail&&job->state!=0xf&&job->state!=0xd)
	{
		printf("incomplete emulation run\n");
		goto err3;
	}

	if(comparator(seq1,job->data))goto err3;

	if(seq2)
	{
		if(!resume)
		{
			printf("expected resume data missing\n");
			goto err2;
		}

		while(job->data)
		{
			e=job->data;
			job->data=e->next;
			free(e);
		}

		job->doesfail=altfail;
		job->failcnt=failcnt;

		for(job->tothello=0;seq2[job->tothello];job->tothello++);

		if(runner(job,altmode,resume,NULL,&tlsver))
		{
			if(!job->doesfail)
			{
				printf("emulation run failed\n");
				goto err3;
			}
		}
		else if(job->doesfail)
		{
			printf("emulation unexpectedly succeeded\n");
			goto err3;
		}

		if(comparator(seq2,job->data))goto err3;
	}

	res=0;

err3:	if(resume)tls_client_free_resume_data(job->context,resume);
err2:	tls_client_fini(job->context);
err1:	while(job->data)
	{
		e=job->data;
		job->data=e->next;
		free(e);
	}
	return res;
}

static void usage(void)
{
	int i;

	fprintf(stderr,"Usage:\n"
		"regressor -2|-3|-t <test> [-p port] <http-server>\n"
		"-2        run all TLSv1.2 related tests\n"
		"-3        run all TLSv1.3 related tests\n"
		"-t        run named test (see list below)\n"
		"-p <port> use specified <http-server> port (default 443)\n"
		"\n"
		"The <http-server> must be configured for TLSv1.2 or TLSv1.3\n"
		"according to the test(s) to be executed.\n\n"
		"Available tests are:\n\n");
	for(i=0;tests[i].name;i++)fprintf(stderr,"%-10s  %s\n",
		tests[i].name,tests[i].desc);
	exit(1);
}

int main(int argc,char *argv[])
{
	int c;
	int i;
	int j;
	int f=0;
	int sel=-1;
	int grp=-1;
	int port=443;
	char *desc=NULL;
	JOB job;

	while((c=getopt(argc,argv,"t:23p:"))!=-1)switch(c)
	{
	case 't':
		if(sel!=-1||grp!=-1)usage();
		for(i=0;tests[i].name;i++)if(!strcmp(optarg,tests[i].name))
			break;
		if(!tests[i].name)usage();
		sel=tests[i].idx;
		desc=tests[i].desc;
		break;
	case '2':
		if(sel!=-1||grp!=-1)usage();
		grp=1;
		break;
	case '3':
		if(sel!=-1||grp!=-1)usage();
		grp=2;
		break;
	case 'p':
		if((port=atoi(optarg))<1||port>65535)usage();
		break;
	default:usage();
	}

	if((sel==-1&&grp==-1)||(argc!=optind+1))usage();

	if(prepare_job(&job,argv[optind],port,500))
	{
		fprintf(stderr,"cannot find %s\n",argv[optind]);
		return 1;
	}

	if(tls_client_global_init())
	{
		fprintf(stderr,"tls_client_global_init failure\n");
		return 1;
	}

	if(sel!=-1)
	{
		printf("%s:\n",desc);
		for(c=0,i=0;regress[i].name;i++)if((c=run_test(&job,i,sel,500)))
			break;
	}
	else if(grp!=-1)for(c=0,j=0;tests[j].name;j++)if(tests[j].bits&grp)
	{
		if(f++)printf("\n");
		printf("%s:\n",tests[j].desc);
		for(i=0;regress[i].name;i++)if((c=run_test(&job,i,j,500)))break;
		if(c)break;
	}

	tls_client_global_fini();

	if(c)
	{
		fprintf(stderr,"tests(s) failed\n");
		return 1;
	}

	return 0;
}
