/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "clientdata.h"
#include "clientdissect.h"
#include "clientloader.h"
#include "clienttables.h"

static unsigned char getgrease1(char *in)
{
	long val;
	char *mem;

	if(!in||strlen(in)!=4||strncasecmp(in,"0x",2))
	{
fail:		return 0x00;
	}
	val=strtol(in,&mem,0);
	if(*mem)goto fail;
	return (unsigned char)(val);
}

static void getgrease2(char *in,unsigned char *out)
{
	long val;
	char *mem;

	if(!in||strlen(in)!=6||strncasecmp(in,"0x",2))
	{
fail:		memset(out,0,2);
		return;
	}
	val=strtol(in,&mem,0);
	if(*mem)goto fail;
	*out++=(unsigned char)(val>>8);
	*out=(unsigned char)(val);
}

static unsigned char *lookup1(const struct id1 *list,char *name)
{
	int i;

	for(i=0;list[i].name;i++)if(!strcasecmp(list[i].name,name))
		return (unsigned char *)(list[i].id);
	return NULL;
}

static unsigned char *lookup2(const struct id2 *list,char *name)
{
	int i;

	for(i=0;list[i].name;i++)if(!strcasecmp(list[i].name,name))
		return (unsigned char *)(list[i].id);
	return NULL;
}

static int add_tlslength(CLIENTHELLO *h,char *arg1,char *arg2)
{
	long val;
	char *mem;

	if(arg2||h->tlslen)return -1;
	if((val=strtol(arg1,&mem,0))<=0||val>65536||*mem||mem==arg1)return -1;
	h->tlslen=val;
	return 0;
}

static int add_envelopetls(CLIENTHELLO *h,char *arg1,char *arg2)
{
	unsigned char *id;

	if(arg2||memcmp(h->envelopetls,"\x00\x00",2))return -1;
	if(!(id=lookup2(tlsver,arg1)))return -1;
	memcpy(h->envelopetls,id,2);
	return 0;
}

static int add_hellotls(CLIENTHELLO *h,char *arg1,char *arg2)
{
	unsigned char *id;

	if(arg2||memcmp(h->hellotls,"\x00\x00",2))return -1;
	if(!(id=lookup2(tlsver,arg1)))return -1;
	memcpy(h->hellotls,id,2);
	return 0;
}

static int add_sessionid(CLIENTHELLO *h,char *arg1,char *arg2)
{
	long val;
	char *mem;

	if(arg2||h->sessionid)return -1;
	if((val=strtol(arg1,&mem,0))<0||val>65536||*mem||mem==arg1)return -1;
	if(!(h->sessionid=malloc(sizeof(DATA)+val)))return -2;
	h->sessionid->size=val;
	return 0;
}

static int add_ciphersuite(CLIENTHELLO *h,char *arg1,char *arg2)
{
	unsigned char *id;
	ID2LIST *l2;
	unsigned char grease[2];

	memset(grease,0,2);
	if(!strcasecmp(arg1,"grease"))
	{
		id=(unsigned char *)"\x0a\x0a";
		getgrease2(arg2,grease);
	}
	else if(arg2)return -1;
	else if(!(id=lookup2(ciphersuites,arg1)))return -1;
	if(!(l2=malloc(sizeof(ID2LIST))))return -2;
	if(h->ciphersuite)
	{
		for(l2=h->ciphersuite;l2->next;l2=l2->next);
		if(!(l2->next=malloc(sizeof(ID2LIST))))return -2;
		l2=l2->next;
	}
	else if(!(h->ciphersuite=l2=malloc(sizeof(ID2LIST))))return -2;
	l2->next=NULL;
	memcpy(l2->id,id,2);
	memcpy(l2->grease,grease,2);
	return 0;
}

static int add_compmeth(CLIENTHELLO *h,char *arg1,char *arg2)
{
	unsigned char *id;
	ID1LIST *l1;

	if(arg2)return -1;
	if(!(id=lookup1(compmeth,arg1)))return -1;
	if(h->compmeth)
	{
		for(l1=h->compmeth;l1->next;l1=l1->next);
		if(!(l1->next=malloc(sizeof(ID1LIST))))return -2;
		l1=l1->next;
	}
	else if(!(h->compmeth=l1=malloc(sizeof(ID1LIST))))return -2;
	l1->next=NULL;
	l1->id=*id;
	return 0;
}

static EXTENSION *add_get_extension(CLIENTHELLO *h,int type,int dups)
{
	EXTENSION *e;

	for(e=h->extension;e;e=e->next)if(!dups&&e->type==type)break;
	if(!e)
	{
		if(h->extension)
		{
			for(e=h->extension;e->next;e=e->next);
			if(!(e->next=malloc(sizeof(EXTENSION))))return NULL;
			e=e->next;
		}
		else if(!(h->extension=e=malloc(sizeof(EXTENSION))))return NULL;
		e->next=NULL;
		e->data=NULL;
		e->type=type;
		memset(e->grease,0,2);
	}
	return e;
}

static int add_ext_sni(CLIENTHELLO *h,char *arg1,char *arg2)
{
	int l;
	EXTENSION *e;
	LIST *ll;

	if(arg2)return -1;
	l=strlen(arg1);
	if(!(e=add_get_extension(h,0x0000,0)))return -2;
	if(e->data)
	{
		for(ll=e->data;ll->next;ll=ll->next);
		if(!(ll->next=malloc(sizeof(LIST)+l+1)))return -2;
		ll=ll->next;
	}
	else if(!(e->data=ll=malloc(sizeof(LIST)+l+1)))return -2;
	ll->next=NULL;
	ll->size=l;
	ll->id=0;
	memcpy(ll->data,arg1,l+1);
	return 0;
}

static int add_ext_suppgroup(CLIENTHELLO *h,char *arg1,char *arg2)
{
	EXTENSION *e;
	ID2LIST *l2;
	unsigned char *id;
	unsigned char grease[2];

	memset(grease,0,2);
	if(!strcasecmp(arg1,"grease"))
	{
		id=(unsigned char *)"\x0a\x0a";
		getgrease2(arg2,grease);
	}
	else if(arg2)return -1;
	else if(!(id=lookup2(group,arg1)))return -1;
	if(!(e=add_get_extension(h,0x000a,0)))return -2;
	if(e->data)
	{
		for(l2=e->data;l2->next;l2=l2->next);
		if(!(l2->next=malloc(sizeof(ID2LIST))))return -2;
		l2=l2->next;
	}
	else if(!(e->data=l2=malloc(sizeof(ID2LIST))))return -2;
	l2->next=NULL;
	memcpy(l2->id,id,2);
	memcpy(l2->grease,grease,2);
	return 0;
}

static int add_ext_expointfmt(CLIENTHELLO *h,char *arg1,char *arg2)
{
	EXTENSION *e;
	ID1LIST *l1;
	unsigned char *id;

	if(arg2)return -1;
	if(!(id=lookup1(ecpointformat,arg1)))return -1;
	if(!(e=add_get_extension(h,0x000b,0)))return -2;
	if(e->data)
	{
		for(l1=e->data;l1->next;l1=l1->next);
		if(!(l1->next=malloc(sizeof(ID1LIST))))return -2;
		l1=l1->next;
	}
	else if(!(e->data=l1=malloc(sizeof(ID1LIST))))return -2;
	l1->next=NULL;
	l1->id=*id;
	return 0;
}

static int add_ext_alpn(CLIENTHELLO *h,char *arg1,char *arg2)
{
	int l;
	EXTENSION *e;
	LIST *ll;
	unsigned char grease[2];

	memset(grease,0,2);
	if(!strcmp(arg1,"grease"))
	{
		arg1="\x0a\x0a";
		getgrease2(arg2,grease);
	}
	else if(arg2)return -1;
	l=strlen(arg1);
	if(!(e=add_get_extension(h,0x0010,0)))return -2;
	if(e->data)
	{
		for(ll=e->data;ll->next;ll=ll->next);
		if(!(ll->next=malloc(sizeof(LIST)+l+1)))return -2;
		ll=ll->next;
	}
	else if(!(e->data=ll=malloc(sizeof(LIST)+l+1)))return -2;
	ll->next=NULL;
	ll->size=l;
	ll->id=0;
	memcpy(ll->data,arg1,l+1);
	memcpy(ll->grease,grease,2);
	return 0;
}

static int add_ext_statusrequest(CLIENTHELLO *h,char *arg1,char *arg2)
{
	long val;
	EXTENSION *e;
	LIST *ll;
	char *mem;
	unsigned char *id;

	if(!arg2)return -1;
	if(!(id=lookup1(statusrequest,arg1)))return -1;
	if((val=strtol(arg2,&mem,0))<0||val>65536||*mem||mem==arg2)return -1;
	if(!(e=add_get_extension(h,0x0005,0)))return -2;
	if(e->data)return -1;
	if(!(e->data=ll=malloc(sizeof(LIST)+val)))return -2;
	ll->next=NULL;
	ll->id=*id;
	ll->size=val;
	return 0;
}

static int add_ext_sigalg(CLIENTHELLO *h,char *arg1,char *arg2)
{
	EXTENSION *e;
	ID2LIST *l2;
	unsigned char *id;
	unsigned char grease[2];

	memset(grease,0,2);
	if(!strcasecmp(arg1,"grease"))
	{
		id=(unsigned char *)"\x0a\x0a";
		getgrease2(arg2,grease);
	}
	else if(arg2)return -1;
	else if(!(id=lookup2(sigalg,arg1)))return -1;
	if(!(e=add_get_extension(h,0x000d,0)))return -2;
	if(e->data)
	{
		for(l2=e->data;l2->next;l2=l2->next);
		if(!(l2->next=malloc(sizeof(ID2LIST))))return -2;
		l2=l2->next;
	}
	else if(!(e->data=l2=malloc(sizeof(ID2LIST))))return -2;
	l2->next=NULL;
	memcpy(l2->id,id,2);
	memcpy(l2->grease,grease,2);
	return 0;
}

static int add_ext_keyshare(CLIENTHELLO *h,char *arg1,char *arg2)
{
	long val;
	EXTENSION *e;
	LIST *ll;
	char *mem;
	unsigned char *id;
	unsigned char grease[2];

	memset(grease,0,2);
	if(!strcasecmp(arg1,"grease"))
	{
		id=(unsigned char *)"\x0a\x0a";
		getgrease2(arg2,grease);
	}
	else if(!arg2)return -1;
	else if(!(id=lookup2(group,arg1)))return -1;
	if((val=strtol(arg2,&mem,0))<0||val>65536||*mem||mem==arg2)return -1;
	if(!(e=add_get_extension(h,0x0033,0)))return -2;
	if(e->data)
	{
		for(ll=e->data;ll->next;ll=ll->next);
		if(!(ll->next=malloc(sizeof(LIST)+val)))return -2;
		ll=ll->next;
	}
	else if(!(e->data=ll=malloc(sizeof(LIST)+val)))return -2;
	ll->next=NULL;
	ll->id=id[0];
	ll->id<<=8;
	ll->id+=id[1];
	ll->size=val;
	memset(ll->data,0,val);
	memcpy(ll->grease,grease,2);
	return 0;
}

static int add_ext_pskkexmode(CLIENTHELLO *h,char *arg1,char *arg2)
{
	EXTENSION *e;
	ID1LIST *l1;
	unsigned char *id;
	unsigned char grease;

	grease=0;
	if(!strcasecmp(arg1,"grease"))
	{
		id=(unsigned char *)"\x0b";
		grease=getgrease1(arg2);
	}
	else if(arg2)return -1;
	else if(!(id=lookup1(pskkeyexchange,arg1)))return -1;
	if(!(e=add_get_extension(h,0x002d,0)))return -2;
	if(e->data)
	{
		for(l1=e->data;l1->next;l1=l1->next);
		if(!(l1->next=malloc(sizeof(ID1LIST))))return -2;
		l1=l1->next;
	}
	else if(!(e->data=l1=malloc(sizeof(ID1LIST))))return -2;
	l1->next=NULL;
	l1->id=*id;
	l1->grease=grease;
	return 0;
}

static int add_ext_suppver(CLIENTHELLO *h,char *arg1,char *arg2)
{
	EXTENSION *e;
	ID2LIST *l2;
	unsigned char *id;
	unsigned char grease[2];

	memset(grease,0,2);
	if(!strcasecmp(arg1,"grease"))
	{
		id=(unsigned char *)"\x0a\x0a";
		getgrease2(arg2,grease);
	}
	else if(arg2)return -1;
	else if(!(id=lookup2(tlsver,arg1)))return -1;
	if(!(e=add_get_extension(h,0x002b,0)))return -2;
	if(e->data)
	{
		for(l2=e->data;l2->next;l2=l2->next);
		if(!(l2->next=malloc(sizeof(ID2LIST))))return -2;
		l2=l2->next;
	}
	else if(!(e->data=l2=malloc(sizeof(ID2LIST))))return -2;
	l2->next=NULL;
	memcpy(l2->id,id,2);
	memcpy(l2->grease,grease,2);
	return 0;
}

static int add_ext_compcert(CLIENTHELLO *h,char *arg1,char *arg2)
{
	EXTENSION *e;
	ID2LIST *l2;
	unsigned char *id;

	if(arg2)return -1;
	if(!(id=lookup2(compcert,arg1)))return -1;
	if(!(e=add_get_extension(h,0x001b,0)))return -2;
	if(e->data)
	{
		for(l2=e->data;l2->next;l2=l2->next);
		if(!(l2->next=malloc(sizeof(ID2LIST))))return -2;
		l2=l2->next;
	}
	else if(!(e->data=l2=malloc(sizeof(ID2LIST))))return -2;
	l2->next=NULL;
	memcpy(l2->id,id,2);
	return 0;
}

static int add_ext_recsizelim(CLIENTHELLO *h,char *arg1,char *arg2)
{
	long val1;
	long val2;
	EXTENSION *e;
	LIST *ll;
	char *mem;

	if(!arg2)return -1;
	if((val1=strtol(arg1,&mem,0))<0||val1>65536||*mem||mem==arg1)return -1;
	if((val2=strtol(arg2,&mem,0))<0||val2>65536||*mem||mem==arg2)return -1;
	if(!(e=add_get_extension(h,0x001c,0)))return -2;
	if(e->data)return -1;
	if(!(e->data=ll=malloc(sizeof(LIST)+val2)))return -2;
	ll->next=NULL;
	ll->id=val1;
	ll->size=val2;
	memset(ll->data,0,val2);
	return 0;
}

static int add_ext_simple(CLIENTHELLO *h,int type,char *len,char *bad,int dup)
{
	int val;
	EXTENSION *e;
	DATA *d;
	char *mem;
	unsigned char grease[2];

	if(type==0x0a0a)getgrease2(bad,grease);
	else if(bad)return -1;
	if((val=strtol(len,&mem,0))<0||val>65536||*mem||mem==len)return -1;
	if(!(e=add_get_extension(h,type,dup)))return -2;
	if(e->data)return -1;
	if(!(e->data=d=malloc(sizeof(DATA)+val)))return -2;
	d->size=val;
	memset(d->data,0,val);
	if(type==0x0a0a)memcpy(e->grease,grease,2);
	return 0;
}

static int add_ext_extmastsec(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0017,arg1,arg2,0);
}

static int add_ext_reneginfo(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0xff01,arg1,arg2,0);
}

static int add_ext_sessticket(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0023,arg1,arg2,0);
}

static int add_ext_psk(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0029,arg1,arg2,0);
}

static int add_ext_sigcertstamp(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0012,arg1,arg2,0);
}

static int add_ext_padding(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0015,arg1,arg2,0);
}

static int add_ext_encthmac(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0016,arg1,arg2,0);
}

static int add_ext_maxfraglen(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0001,arg1,arg2,0);
}

static int add_ext_clicerturl(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0002,arg1,arg2,0);
}

static int add_ext_trustcakey(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0003,arg1,arg2,0);
}

static int add_ext_trunchmac(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0004,arg1,arg2,0);
}

static int add_ext_usermap(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0006,arg1,arg2,0);
}

static int add_ext_cliauthz(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0007,arg1,arg2,0);
}

static int add_ext_srvauthz(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0008,arg1,arg2,0);
}

static int add_ext_certtype(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0009,arg1,arg2,0);
}

static int add_ext_srp(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x000c,arg1,arg2,0);
}

static int add_ext_usesrtp(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x000e,arg1,arg2,0);
}

static int add_ext_heartbeat(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x000f,arg1,arg2,0);
}

static int add_ext_statreqv2(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0011,arg1,arg2,0);
}

static int add_ext_clicerttype(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0013,arg1,arg2,0);
}

static int add_ext_svrcerttype(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0014,arg1,arg2,0);
}

static int add_ext_tokenbind(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0018,arg1,arg2,0);
}

static int add_ext_cachedinfo(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0019,arg1,arg2,0);
}

static int add_ext_tlslts(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x001a,arg1,arg2,0);
}

static int add_ext_pwprot(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x001d,arg1,arg2,0);
}

static int add_ext_pwclr(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x001e,arg1,arg2,0);
}

static int add_ext_pwsalt(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x001f,arg1,arg2,0);
}

static int add_ext_ticketpin(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0020,arg1,arg2,0);
}

static int add_ext_certextpsk(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0021,arg1,arg2,0);
}

static int add_ext_delcred(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0022,arg1,arg2,0);
}

static int add_ext_ektcipher(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0027,arg1,arg2,0);
}

static int add_ext_earlydta(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x002a,arg1,arg2,0);
}

static int add_ext_cookie(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x002c,arg1,arg2,0);
}

static int add_ext_certauth(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x002f,arg1,arg2,0);
}

static int add_ext_oidflt(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0030,arg1,arg2,0);
}

static int add_ext_posthsauth(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0031,arg1,arg2,0);
}

static int add_ext_sigalgcert(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0032,arg1,arg2,0);
}

static int add_ext_transinfo(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0034,arg1,arg2,0);
}

static int add_ext_connid(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0035,arg1,arg2,0);
}

static int add_ext_extidhash(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0037,arg1,arg2,0);
}

static int add_ext_extsessid(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0038,arg1,arg2,0);
}

static int add_ext_grease(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x0a0a,arg1,arg2,1);
}

static int add_ext_onxtprotoneg(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x3374,arg1,arg2,0);
}

static int add_ext_obndcert(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x3377,arg1,arg2,0);
}

static int add_ext_encclicert(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x337c,arg1,arg2,0);
}

static int add_ext_tobitst(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x5500,arg1,arg2,0);
}

static int add_ext_ochnid(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x754f,arg1,arg2,0);
}

static int add_ext_chnid(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x7550,arg1,arg2,0);
}

static int add_ext_newpad(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0x8b47,arg1,arg2,0);
}

static int add_ext_tlsdraft(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0xff02,arg1,arg2,0);
}

static int add_ext_shhdr(CLIENTHELLO *h,char *arg1,char *arg2)
{
	return add_ext_simple(h,0xff03,arg1,arg2,0);
}

static struct
{
	char *name;
	int (*func)(CLIENTHELLO *h,char *arg1,char *arg2);
} parsetab[]=
{
	{"tls-length",add_tlslength},
	{"envelope-tls",add_envelopetls},
	{"hello-tls",add_hellotls},
	{"session-id",add_sessionid},
	{"ciphersuite",add_ciphersuite},
	{"compression-method",add_compmeth},
	{"extension-sni-hostname",add_ext_sni},
	{"extension-max-fragment-length",add_ext_maxfraglen},
	{"extension-client-certificate-url",add_ext_clicerturl},
	{"extension-trusted-ca-keys",add_ext_trustcakey},
	{"extension-truncated-hmac",add_ext_trunchmac},
	{"extension-status-request",add_ext_statusrequest},
	{"extension-user-mapping",add_ext_usermap},
	{"extension-client-authz",add_ext_cliauthz},
	{"extension-server-authz",add_ext_srvauthz},
	{"extension-cert-type",add_ext_certtype},
	{"extension-supported-group",add_ext_suppgroup},
	{"extension-ec-point-format",add_ext_expointfmt},
	{"extension-srp",add_ext_srp},
	{"extension-signature-algorithm",add_ext_sigalg},
	{"extension-use-srtp",add_ext_usesrtp},
	{"extension-heartbeat",add_ext_heartbeat},
	{"extension-alpn",add_ext_alpn},
	{"extension-status-request-v2",add_ext_statreqv2},
	{"extension-signed-certificate-timestamp",add_ext_sigcertstamp},
	{"extension-client-certificate-type",add_ext_clicerttype},
	{"extension-server-certificate-type",add_ext_svrcerttype},
	{"extension-padding",add_ext_padding},
	{"extension-encrypt-then-mac",add_ext_encthmac},
	{"extension-extended-master-secret",add_ext_extmastsec},
	{"extension-token-binding",add_ext_tokenbind},
	{"extension-cached-info",add_ext_cachedinfo},
	{"extension-tls-lts",add_ext_tlslts},
	{"extension-compress-certificate",add_ext_compcert},
	{"extension-record-size-limit",add_ext_recsizelim},
	{"extension-pwd-protect",add_ext_pwprot},
	{"extension-pwd-clear",add_ext_pwclr},
	{"extension-password-salt",add_ext_pwsalt},
	{"extension-ticket-pinning",add_ext_ticketpin},
	{"extension-tls-cert-with-extern-psk",add_ext_certextpsk},
	{"extension-delegated-credentials",add_ext_delcred},
	{"extension-session-ticket",add_ext_sessticket},
	{"extension-supported-ekt-ciphers",add_ext_ektcipher},
	{"extension-pre-shared-key",add_ext_psk},
	{"extension-early-data",add_ext_earlydta},
	{"extension-supported-version",add_ext_suppver},
	{"extension-cookie",add_ext_cookie},
	{"extension-psk-key-exchange-mode",add_ext_pskkexmode},
	{"extension-certificate-authorities",add_ext_certauth},
	{"extension-oid-filters",add_ext_oidflt},
	{"extension-post-handshake-auth",add_ext_posthsauth},
	{"extension-signature-algorithms-cert",add_ext_sigalgcert},
	{"extension-key-share",add_ext_keyshare},
	{"extension-transparency-info",add_ext_transinfo},
	{"extension-connection-id",add_ext_connid},
	{"extension-external-id-hash",add_ext_extidhash},
	{"extension-external-session-id",add_ext_extsessid},
	{"extension-grease",add_ext_grease},
	{"extension-old-next-protocol-negotiation",add_ext_onxtprotoneg},
	{"extension-origin-bound-certificates",add_ext_obndcert},
	{"extension-encrypted-client-certificates",add_ext_encclicert},
	{"extension-token-binding-test",add_ext_tobitst},
	{"extension-old-channel-id",add_ext_ochnid},
	{"extension-channel-id",add_ext_chnid},
	{"extension-new-padding",add_ext_newpad},
	{"extension-renegotiation-info",add_ext_reneginfo},
	{"extension-tls-draft",add_ext_tlsdraft},
	{"extension-short-header",add_ext_shhdr},
	{NULL,NULL}
};

CLIENTHELLO *load_clienthello(char *fn,FILE *fp)
{
	int i;
	int line=0;
	char *arg1;
	char *arg2;
	char *arg3;
	char *mem;
	CLIENTHELLO *h;

	char bfr[1024];

	if(!fp)if(!(fp=fopen(fn,"re")))
	{
		perror("fopen");
		goto err1;
	}

	if(!(h=malloc(sizeof(CLIENTHELLO))))
	{
		fprintf(stderr,"out of memory\n");
		goto err2;
	}
	memset(h,0,sizeof(CLIENTHELLO));

	while(fgets(bfr,sizeof(bfr),fp))
	{
		line++;
		if(!(arg1=strtok_r(bfr," \t\r\n",&mem))||!*arg1||*arg1=='#')
			continue;
		if(!(arg2=strtok_r(NULL," \t\r\n",&mem))||!*arg2)
		{
			fprintf(stderr,"argument error line %d\n",line);
			goto err3;
		}
		if((arg3=strtok_r(NULL," \t\r\n",&mem))&&!*arg3)
		{
			fprintf(stderr,"argument error line %d\n",line);
			goto err3;
		}
		for(i=0;parsetab[i].name;i++)
			if(!strcasecmp(parsetab[i].name,arg1))break;
		if(!parsetab[i].name)
		{
			fprintf(stderr,"unknown statement line %d\n",line);
			goto err3;
		}
		switch(parsetab[i].func(h,arg2,arg3))
		{
		case -1:fprintf(stderr,"syntax error line %d\n",line);
			goto err3;
		case -2:fprintf(stderr,"out of memory\n");
			goto err3;
		}
	}

	if(!h->tlslen)
	{
		fprintf(stderr,"missing tls-length\n");
		goto err3;
	}

	if(!memcmp(h->envelopetls,"\x00\x00",2))
	{
		fprintf(stderr,"missing envelope-tls\n");
		goto err3;
	}

	if(!memcmp(h->hellotls,"\x00\x00",2))
	{
		fprintf(stderr,"missing hello-tls\n");
		goto err3;
	}

	fclose(fp);
	return h;

err3:	free_clienthello(h);
err2:	fclose(fp);
err1:	return NULL;
}
