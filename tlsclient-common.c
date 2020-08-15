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
#include <stdio.h>
#include "tlsdispatch.h"
#include "tlsclient.h"

#ifndef NO_EMU

#include "clientdata.h"
#include "clientdissect.h"
#include "clientconstruct.h"
#include "clientcompose.h"
#include "clientloader.h"

__thread STATE state={NULL,0,0,0,0,0,0};

#endif

#define ALL_LIBS	3

static WRAPPER *lib[ALL_LIBS]=
{
#ifdef USE_OPENSSL
	&openssl,
#else
	NULL,
#endif
#ifdef USE_MBEDTLS
	&mbedtls,
#else
	NULL,
#endif
#ifdef USE_GNUTLS
	&gnutls,
#else
	NULL,
#endif
};

int tls_client_global_init(void)
{
	int i;

	for(i=0;i<ALL_LIBS;i++)if(lib[i]&&lib[i]->tls_client_global_init())
	{
		while(i-->0)if(lib[i])lib[i]->tls_client_global_fini();
		return -1;
	}
	return 0;
}

void tls_client_global_fini(void)
{
	int i;

	for(i=0;i<ALL_LIBS;i++)if(lib[i])lib[i]->tls_client_global_fini();
}

void *tls_client_init(int mode)
{
	void *ctx;
	int libid;
	int tlsver;
	int emu;
	COMMON *cmn;

	libid=(mode>>24)&0xff;
	tlsver=mode&0x00ff0000;
	emu=mode&0x0000ffff;

	if(libid>ALL_LIBS)return NULL;

	if(!libid)while(libid<ALL_LIBS)if(lib[libid++])break;
	libid--;

	if(!lib[libid])return NULL;

	if(!(ctx=lib[libid]->tls_client_init(tlsver,emu)))return NULL;
	cmn=*((COMMON **)ctx);
	cmn->libid=libid;
#ifndef NO_EMU
	cmn->emuidx=-1;
	cmn->emuopt=0;
	cmn->emumode=-1;
	cmn->emulation=NULL;
	memset(cmn->emu,0,sizeof(cmn->emu));
#endif
	return ctx;
}

void tls_client_fini(void *context)
{
	COMMON *cmn=*((COMMON **)context);
#ifndef NO_EMU
	CHAIN *r;
	int i;

	for(i=0;i<MAXGROUPS;i++)while(cmn->emu[i])
	{
		r=cmn->emu[i];
		cmn->emu[i]=r->next;
		free_clienthello(r->template);
		free(r);
	}
#endif
	lib[cmn->libid]->tls_client_fini(context);
}

int tls_client_add_cafile(void *context,char *fn)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_add_cafile(context,fn);
}

int tls_client_add_client_cert(void *context,char *cert,char *key,
	int (*tls_getpass)(char *bfr,int size,char *prompt),char *prompt)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_add_client_cert(context,cert,key,
		tls_getpass,prompt);
}

int tls_client_set_alpn(void *context,int nproto,char **proto)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_set_alpn(context,nproto,proto);
}

int tls_client_load_hello_template(void *context,int group,char *fn)
{
#ifndef NO_EMU
	COMMON *cmn=*((COMMON **)context);
	CHAIN *ch;
	CHAIN *r;
	void *tmpl;

	if(group<0||group>=MAXGROUPS)return -1;
	if(!(tmpl=load_clienthello(fn,NULL)))return -1;
	if(!(ch=malloc(sizeof(CHAIN))))
	{
		free_clienthello(tmpl);
		return -1;
	}
	ch->next=NULL;
	ch->template=tmpl;
	if(!cmn->emu[group])cmn->emu[group]=ch;
	else
	{
		for(r=cmn->emu[group];r->next;r=r->next);
		r->next=ch;
	}
	return 0;
#else
	return -1;
#endif
}

int tls_client_use_hello_template(void *context,int group,int option)
{
#ifndef NO_EMU
	COMMON *cmn=*((COMMON **)context);

	if(group<-1||group>=MAXGROUPS)return -1;
	if(group!=-1)if(!cmn->emu[group])return -1;
	cmn->emuidx=group;
	cmn->emuopt=option;
	return 0;
#else
	return -1;
#endif
}

void *tls_client_connect(void *context,int fd,int timeout,char *host,int verify,
	void *resume)
{
	COMMON *cmn=*((COMMON **)context);

#ifndef NO_EMU
	memset(&state,0,sizeof(state));
	if(cmn->emuidx!=-1)state.ref=cmn->emu[cmn->emuidx];
	state.user=cmn->emuopt;
#endif
	return lib[cmn->libid]->tls_client_connect(context,fd,timeout,host,
		verify,resume);
}

void tls_client_disconnect(void *context,void **resume)
{
	COMMON *cmn=*((COMMON **)context);

	lib[cmn->libid]->tls_client_disconnect(context,resume);
}

int tls_client_resume_data_lifetime_hint(void *context,void *resume)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_resume_data_lifetime_hint(resume);
}

void tls_client_free_resume_data(void *context,void *resume)
{
	COMMON *cmn=*((COMMON **)context);

	lib[cmn->libid]->tls_client_free_resume_data(resume);
}

char *tls_client_get_alpn(void *context)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_get_alpn(context);
}

int tls_client_get_tls_version(void *context)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_get_tls_version(context);
}

unsigned int tls_client_get_emulation_error(void)
{
	unsigned int status=0;

#ifndef NO_EMU
	if(state.other)status|=TLS_CLIENT_EMU_STATUS_OPTION_ERROR;
	if(state.error)status|=TLS_CLIENT_EMU_STATUS_MODIFY_ERROR;
	if(state.txerr)status|=TLS_CLIENT_EMU_STATUS_TX_ERROR;
	if(state.rxerr)status|=TLS_CLIENT_EMU_STATUS_RX_ERROR;
	if(state.nettx>15)status|=0xf<<4;
	else status|=state.nettx<<4;
	if(state.netrx>15)status|=0xf;
	else status|=state.netrx;
#endif
	return status;
}

int tls_client_write(void *context,void *data,int len)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_write(context,data,len);
}

int tls_client_read(void *context,void *data,int len)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_read(context,data,len);
}

int tls_client_get_max_tls_version(void *context)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_get_max_tls_version(context);
}

int tls_client_set_max_tls_version(void *context,int version)
{
	COMMON *cmn=*((COMMON **)context);

	return lib[cmn->libid]->tls_client_set_max_tls_version(context,version);
}

/* called by patched tls library to modify the library's client hello */

int tls_client_hello_modify(void *buffer,int fill,int max,unsigned char *random,
	int randlen,int tlshdr,int mode)
{
#ifndef NO_EMU
	int l;
	int asis=0;
	void *src=NULL;
	void *dst=NULL;
	unsigned char bfr[1024];

	if(!state.ref)goto err1;

	switch(mode)
	{
	case 2:
	case 3:	asis=1;
		mode-=2;
	case 0:
	case 1:	if(!mode&&state.binder)
		{
			state.binder=0;
			goto err1;
		}
		if(mode)state.binder=1;
		if(!(src=dissect_clienthello(buffer,fill,tlshdr,0,asis)))
			goto err2;
		if(tlshdr<0)tlshdr=0;
		if(!(dst=new_clienthello(src)))goto err3;
		if(modify_clienthello(dst,src,state.ref->template,tlshdr,1,
			(state.user&TLS_CLIENT_EMU_USE_STATIC_GREASE)?1:0,
			random,randlen,asis))goto err4;
		if((l=compose_clienthello(dst,bfr,sizeof(bfr),tlshdr))==-1)
			goto err4;
		memcpy(buffer,bfr,l);
		if(state.ref->next)state.ref=state.ref->next;
		if(state.user&TLS_CLIENT_EMU_FF68A10_RETRY&&!state.step)
			state.step=1;
		return l-fill;

	case 4: if((l=modify_clienthellocipher(buffer,fill,max,
			state.ref->template,1,
			(state.user&TLS_CLIENT_EMU_USE_STATIC_GREASE)?1:0,
			random,randlen))==-1)goto err2;
		return l-fill;

	case 5:	if((l=modify_clienthellocomp(buffer,fill,max,
			state.ref->template,
			(state.user&TLS_CLIENT_EMU_USE_STATIC_GREASE)?1:0))==-1)
				goto err2;
		return l-fill;

	case 6:	return find_psk_in_clienthello(buffer,fill);
	}

err4:   if(dst)free_clienthello(dst);
err3:   if(src)free_clienthello(src);
err2:   state.error++;
err1:   return 0;
#else
	return 0;
#endif
}
