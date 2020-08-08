/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "clientdata.h"
#include "clientdissect.h"
#include "clientdump.h"

#define BUFSIZE 65536

static int listensocket(char *host,int port)
{
	int s;
	int x;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in a4;
		struct sockaddr_in6 a6;
	} addr;
	struct linger l;

	memset(&addr,0,sizeof(addr));
	if(inet_pton(AF_INET,host,&addr.a4.sin_addr)==1)
	{
		addr.a4.sin_family=AF_INET;
		addr.a4.sin_port=htons(port);
	}
	else if(inet_pton(AF_INET6,host,&addr.a6.sin6_addr)==1)
	{
		addr.a6.sin6_family=AF_INET6;
		addr.a6.sin6_port=htons(port);
	}
	else goto err1;

	if((s=socket(addr.sa.sa_family,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
		0))==-1)goto err1;
	x=1;
	if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&x,sizeof(x)))goto err2;
	x=0;
	if(setsockopt(s,SOL_SOCKET,SO_OOBINLINE,&x,sizeof(x)))goto err2;
	x=1;
	if(addr.sa.sa_family==AF_INET6)
		if(setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,&x,sizeof(x)))
			goto err2;
	if(bind(s,&addr.sa,sizeof(addr)))goto err2;
	l.l_onoff=1;
	l.l_linger=10;
	if(setsockopt(s,SOL_SOCKET,SO_LINGER,&l,sizeof(l)))goto err2;
	x=1;
	if(setsockopt(s,SOL_TCP,TCP_NODELAY,&x,sizeof(x)))goto err2;
	if(listen(s,256))goto err2;
	return s;

err2:	close(s);
err1:	return -1;
}

static int doconnect(char *host,int port)
{
	int s;
	int l;
	socklen_t sl;
	struct pollfd p;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in a4;
		struct sockaddr_in6 a6;
	} addr;

	memset(&addr,0,sizeof(addr));
	if(inet_pton(AF_INET,host,&addr.a4.sin_addr)==1)
	{
		addr.a4.sin_family=AF_INET;
		addr.a4.sin_port=htons(port);
	}
	else if(inet_pton(AF_INET6,host,&addr.a6.sin6_addr)==1)
	{
		addr.a6.sin6_family=AF_INET6;
		addr.a6.sin6_port=htons(port);
	}
	else return -1;

	if((s=socket(addr.sa.sa_family,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
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

	if(connect(s,&addr.sa,sizeof(addr)))
	{
		if(errno==EINPROGRESS)
		{
			switch(poll(&p,1,-1))
			{
			case -1:perror("poll");
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

static int tcpforward(int lcl,int rmt)
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
			return -1;
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
			else lrfill+=len;

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

	return 0;
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

static int dump_clienthello_packet(void *packet,int length,int showgrease)
{
	void *src;

	if(!(src=dissect_clienthello(packet,length,1,1,0)))return -1;
	dump_clienthello(src,showgrease,NULL,0);
	free_clienthello(src);
	return 0;
}

static int str2hex(char *in,unsigned char *out)
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

static int stdin2bfr(unsigned char *out,int max)
{
	int l=0;
	int n;
	char pair[2];

	while((n=read(0,pair,2))==2)
	{
		if(pair[0]=='\r'||pair[0]=='\n')return l;
		if(l==max)return -1;
		if(str2hex(pair,out+l++))return -1;
	}
	if(n==1)
	{
		if(pair[0]=='\r'||pair[0]=='\n')return l;
		return -1;
	}
	return l;
}

static int arg2bfr(char *in,unsigned char *out,int max)
{
	int i;
	int l;

	for(i=0,l=0;in[i];i+=2,l++)
	{
		if(l==max)return -1;
		if(str2hex(&in[i],out+l))return -1;
	}
	return l;
}

static void usage(void)
{
	fprintf(stderr,"Usage:\n"
	"tlshelloanalyzer [-l <listen-ip>] [-p <listen-port>] [-g|-r|-h]\n"
	"tlshelloanalyzer -i[<hexstream>] [-g|-r]\n"
	"tlshelloanalyzer -L <hexstream> -R <hexstream> [-g|-b]\n"
	"-l <listen-ip>    listen ip, default is 127.0.0.1\n"
	"-p <listen-port>  listening port, default 443\n"
	"-f <forward-ip>   forwarding ip\n"
	"-P <forward-port> forwarding port, default 443\n"
	"-n <count>        no hello reply count before forwarding (default 1)\n"
	"-y <count>        forwarding count before -n applies (default 0)\n"
	"-i                read Wireshark hex stream from stdin or cmdline\n"
	"-L <hexstream>    Wireshark hex stream for left side of diff\n"
	"-R <hexstream>    Wireshark hex stream for right side of diff\n"
	"-O <hexstream>    obfuscate SNI hostname in Wireshark hex stream\n"
	"-g                show grease values\n"
	"-b                do binary instead of textual comparison\n"
	"-r                raw hex dump instead of textual output\n"
	"-h                Wireshark hex stream instead of textual output\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int s;
	int l;
	int c;
	int i;
	int raw=0;
	int hex=0;
	int bin=0;
	int showgrease=0;
	int usestdin=0;
	int port=443;
	int fport=443;
	int silent=1;
	int allow=0;
	char *host="127.0.0.1";
	char *fwd=NULL;
	char *in=NULL;
	char *left=NULL;
	char *right=NULL;
	char *obfuscate=NULL;
	void *ll;
	void *rr;
	struct pollfd p;
	unsigned char bfr[1024];
	unsigned char bfr2[1024];

	while((c=getopt(argc,argv,"l:p:rgi::L:R:hbO:n:f:P:y:"))!=-1)switch(c)
	{
	case 'l':
		host=optarg;
		break;
	case 'p':
		if((port=atoi(optarg))<1||port>65535)usage();
		break;
	case 'r':
		raw=1;
		break;
	case 'g':
		showgrease=1;
		break;
	case 'i':
		in=optarg;
		usestdin=1;
		break;
	case 'L':
		left=optarg;
		break;
	case 'R':
		right=optarg;
		break;
	case 'h':
		hex=1;
		break;
	case 'b':
		bin=1;
		break;
	case 'O':
		obfuscate=optarg;
		break;
	case 'n':
		if((silent=atoi(optarg))<0||silent>9)usage();
		break;
	case 'y':
		if((allow=atoi(optarg))<0||allow>9)usage();
		break;
	case 'f':
		fwd=optarg;
		break;
	case 'P':
		if((fport=atoi(optarg))<1||fport>65535)usage();
		break;
	default:usage();
	}

	if(optind!=argc)usage();

	if((!left&&right)||(right&&!left))usage();

	if(obfuscate)
	{
		if((l=arg2bfr(obfuscate,bfr,sizeof(bfr)))==-1)goto err;
		if(obfuscate_clienthello(bfr,l))goto err;
		for(i=0;i<l;i++)printf("%02x",bfr[i]);
		printf("\n");
		return 0;
	}

	if(left)
	{
		if(!right)usage();
		if((l=arg2bfr(left,bfr,sizeof(bfr)))==-1)goto err;
		if((i=arg2bfr(right,bfr2,sizeof(bfr2)))==-1)goto err;

		if(bin)
		{
			if(cmp_clienthello(bfr,l,bfr2,i))goto err;
			return 0;
		}

		if(!(ll=dissect_clienthello(bfr,l,1,1,0)))goto err;
		if(!(rr=dissect_clienthello(bfr2,i,1,1,0)))
		{
			free_clienthello(ll);
			goto err;
		}
		l=diff_clienthello(ll,rr,showgrease,0);
		free_clienthello(ll);
		free_clienthello(rr);
		if(l<0)goto err;
		return 0;
	}

	if(usestdin)
	{
		if(in)
		{
			if((l=arg2bfr(in,bfr,sizeof(bfr)))==-1)goto err;
		}
		else if((l=stdin2bfr(bfr,sizeof(bfr)))==-1)goto err;
		if(raw)
		{
			for(i=0;i<l;i++)
			{
				if(!(i%16))printf("%04x:",i);
				printf(" %02x",bfr[i]);
				if(!((i+1)%16)&&i!=l-1)printf("\n");
			}
			printf("\n\n");
		}
		else if(!dump_clienthello_packet(bfr,l,showgrease))printf("\n");
		else goto err;
		return 0;
	}

	if((s=listensocket(host,port))==-1)
	{
		fprintf(stderr,"cannot listen on %s port %d\n",host,port);
		return 1;
	}

	p.fd=s;
	p.events=POLLIN;

	while(1)
	{
		while(poll(&p,1,-1)<1);
		if((c=accept4(s,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC))==-1)
			continue;
		if(fwd)
		{
			if(allow)allow--;
			else if(silent)
			{
				if(read_hello(c,bfr,sizeof(bfr))==-1)
				{
					shutdown(c,SHUT_RDWR);
					close(c);
					continue;
				}
				silent--;
				shutdown(c,SHUT_RDWR);
				close(c);
				continue;
			}
			l=0;
			if(l!=-1)if((i=doconnect(fwd,fport))!=-1)
			{
				tcpforward(c,i);
				shutdown(i,SHUT_RDWR);
				close(i);
			}
			shutdown(c,SHUT_RDWR);
			close(c);
			continue;
		}
		if((l=read_hello(c,bfr,sizeof(bfr)))!=-1)
		{
			if(hex)
			{
				for(i=0;i<l;i++)printf("%02x",bfr[i]);
				printf("\n\n");
			}
			else if(raw)
			{
				for(i=0;i<l;i++)
				{
					if(!(i%16))printf("%04x:",i);
					printf(" %02x",bfr[i]);
					if(!((i+1)%16)&&i!=l-1)printf("\n");
				}
				printf("\n\n");
			}
			else if(!dump_clienthello_packet(bfr,l,showgrease))
				printf("\n");
		}
		shutdown(c,SHUT_RDWR);
		close(c);
	}
	return 0;

err:	fprintf(stderr,"Failed.\n");
	return 1;
}
