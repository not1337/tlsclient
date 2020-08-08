/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <stdlib.h>
#include <string.h>
#include "clientdata.h"
#include "clientconstruct.h"

#if 0
#include <stdio.h>
#define BAD(a) fprintf(stderr,a)
#define BAD2(a,b) fprintf(stderr,a,b)
#else
#define BAD(a)
#define BAD2(a,b)
#endif

typedef struct
{
	unsigned char *random;
	int len;
	int pos;
	int extmap;
} RND;

static const unsigned char grease1[8]=
{
	0x0B,0x2A,0x49,0x68,0x87,0xA6,0xC5,0xE4
};

static int getgreaseidx(RND *rnd)
{
	int idx;

	if(rnd->len)
	{
		idx=rnd->random[rnd->pos>>1];
		if(rnd->pos&1)idx>>=4;
		else idx&=0xf;
		if(((++(rnd->pos))>>1)>=rnd->len)rnd->pos=0;
	}
	else idx=0;

	return idx;
}

static unsigned char getgrease1(RND *rnd,int usestatic,unsigned char grease)
{
	int idx;

	if(usestatic&&grease)idx=grease>>4;
	else idx=getgreaseidx(rnd);

	return grease1[idx&0x7];
}

static int getgrease2(RND *rnd,unsigned char *dest,int isext,int usestatic,
	unsigned char *grease)
{
	int idx;

	if(usestatic&&memcmp(grease,"\x00\x00",2))idx=grease[0]>>4;
	else idx=getgreaseidx(rnd);

	if(isext)if(rnd->extmap!=0xffff)
	{
		while(rnd->extmap&(1<<idx))idx=(idx+1)&0xf;
		rnd->extmap|=(1<<idx);
	}

	idx<<=4;
	idx|=0xa;

	if(dest)
	{
		*dest++=(unsigned char)idx;
		*dest++=(unsigned char)idx;
	}

	return (idx<<8)|idx;
}

static int pseudogrease2(RND *rnd,int *idx,unsigned char *dest,int isext,
	int usestatic,unsigned char *grease)
{
	int val=*idx;

	if(usestatic&&memcmp(grease,"\x00\x00",2))val=grease[0]>>4;
	else *idx=(*idx+3)&0xf;

	if(isext)if(rnd->extmap!=0xffff)
	{
		while(rnd->extmap&(1<<val))val=(val+1)&0xf;
		rnd->extmap|=(1<<val);
	}

	val<<=4;
	val|=0xa;


	if(dest)
	{
		*dest++=(unsigned char)val;
		*dest++=(unsigned char)val;
	}

	return (val<<8)|val;
}

static int join_alpn(LIST **dll,LIST **srl,LIST *rll,RND *rnd,int usestatic)
{
	LIST *ll;
	LIST **sll;

	for(;rll;rll=rll->next)
	{
		for(sll=srl;*sll;sll=&(*sll)->next)
		{
			ll=*sll;
			if(rll->size==ll->size)
				if(!memcmp(rll->data,ll->data,rll->size))break;
		}
		if(*sll)
		{
			*sll=ll->next;
		}
		else if(rll->size==2&&!memcmp(rll->data,"\x0a\x0a",2))
		{
			if(!(ll=malloc(sizeof(LIST)+rll->size+1)))return -1;
			ll->data[rll->size]=0;
			getgrease2(rnd,ll->data,0,usestatic,ll->grease);
			ll->size=rll->size;
		}
		else continue;
		ll->next=NULL;
		*dll=ll;
		dll=&ll->next;
	}
	return 0;
}

static int join_list(LIST **dll,LIST **srl,LIST *rll,RND *rnd,int usestatic,
	int pseudo)
{
	LIST *ll;
	LIST **sll;

	for(;rll;rll=rll->next)
	{
		for(sll=srl;*sll;sll=&(*sll)->next)
		{
			ll=*sll;
			if(rll->id==ll->id)break;
		}
		if(*sll)
		{
			*sll=ll->next;
		}
		else if(rll->id==0x0a0a)
		{
			if(!(ll=malloc(sizeof(LIST)+rll->size)))return -1;
			memset(ll->data,0,rll->size);
			if(pseudo!=-1)ll->id=pseudogrease2(rnd,&pseudo,NULL,0,
				usestatic,ll->grease);
			else ll->id=getgrease2(rnd,NULL,0,usestatic,ll->grease);
			ll->size=rll->size;
		}
		else continue;
		ll->next=NULL;
		*dll=ll;
		dll=&ll->next;
	}
	return 0;
}

static int join_id1(ID1LIST **dl1,ID1LIST **sr1,ID1LIST *rl1,RND *rnd,int g,
	int usestatic)
{
	ID1LIST *l1;
	ID1LIST **sl1;

	for(;rl1;rl1=rl1->next)
	{
		for(sl1=sr1;*sl1;sl1=&(*sl1)->next)
		{
			l1=*sl1;
			if(rl1->id==l1->id)break;
		}
		if(*sl1)
		{
			*sl1=l1->next;
			l1->next=NULL;
			*dl1=l1;
			dl1=&l1->next;
		}
		else if(!g);
		else if(rl1->id==0x0b)
		{
			if(!(l1=malloc(sizeof(ID1LIST))))return -1;
			l1->id=getgrease1(rnd,usestatic,l1->grease);
			l1->next=NULL;
			*dl1=l1;
			dl1=&l1->next;
		}
	}
	return 0;
}

static int join_id2(ID2LIST **dl2,ID2LIST **sr2,ID2LIST *rl2,int add,RND *rnd,
	int usestatic,int pseudo)
{
	ID2LIST *l2;
	ID2LIST **sl2;

	for(;rl2;rl2=rl2->next)
	{
		for(sl2=sr2;*sl2;sl2=&(*sl2)->next)
		{
			l2=*sl2;
			if(!memcmp(rl2->id,l2->id,2))break;
		}
		if(*sl2)*sl2=l2->next;
		else if(!memcmp(rl2->id,"\x0a\x0a",2))
		{
			if(!(l2=malloc(sizeof(ID2LIST))))return -1;
			if(pseudo!=-1)pseudogrease2(rnd,&pseudo,l2->id,0,
				usestatic,l2->grease);
			else getgrease2(rnd,l2->id,0,usestatic,l2->grease);
		}
		else if(!add)continue;
		else
		{
			if(!(l2=malloc(sizeof(ID2LIST))))return -1;
			memcpy(l2->id,rl2->id,2);
		}
		l2->next=NULL;
		*dl2=l2;
		dl2=&l2->next;
	}
	return 0;
}

int modify_clienthello(CLIENTHELLO *dst,CLIENTHELLO *src,CLIENTHELLO *ref,
	int tlshdr,int add,int staticgrease,unsigned char *random,int randlen,
	int asis)
{
	EXTENSION *re;
	EXTENSION **de;
	EXTENSION *e;
	DATA *rd;
	DATA *nd;
	int baseidx;
	RND rnd;

	rnd.random=random;
	rnd.len=randlen;
	rnd.pos=0;
	rnd.extmap=0;

	baseidx=getgreaseidx(&rnd);

	dst->tlslen=ref->tlslen;

	if(tlshdr)
	{
		if(memcmp(src->envelopetls,ref->envelopetls,2))
		{
			BAD("envelope tls mismatch\n");
			goto err1;
		}
		memcpy(dst->envelopetls,src->envelopetls,2);
	}

	if(memcmp(src->hellotls,ref->hellotls,2))
	{
		BAD("hello tls mismatch\n");
		goto err1;
	}
	memcpy(dst->hellotls,src->hellotls,2);

	if(src->sessionid&&!ref->sessionid)dst->sessionid=NULL;
	else if(!src->sessionid&&ref->sessionid)
	{
		BAD("session mismatch\n");
		goto err1;
	}
	else
	{
		dst->sessionid=src->sessionid;
		src->sessionid=NULL;
	}

	if(asis)
	{
		dst->ciphersuite=src->ciphersuite;
		src->ciphersuite=NULL;
	}
	else if(join_id2(&dst->ciphersuite,&src->ciphersuite,ref->ciphersuite,
		add,&rnd,staticgrease,-1))
	{
		BAD("ciphersuite problem\n");
		goto err1;
	}

	if(asis)
	{
		dst->compmeth=src->compmeth;
		src->compmeth=NULL;
	}
	else if(join_id1(&dst->compmeth,&src->compmeth,ref->compmeth,&rnd,0,
		staticgrease))
	{
		BAD("compression method problem\n");
		goto err1;
	}

	for(de=&dst->extension,re=ref->extension;re;re=re->next)
	{
		for(e=src->extension;e;e=e->next)if(e->type==re->type)break;

		if(!e)
		{
			switch(re->type)
			{
			case 0x0017:
				rd=re->data;
				if(rd->size)break;
			case 0x0a0a:
			case 0xff01:
				if(!(e=malloc(sizeof(EXTENSION))))
				{
					BAD("malloc failure\n");
					goto err1;
				}
				memset(e,0,sizeof(EXTENSION));
				if(re->type!=0x0a0a)e->type=re->type;
				else e->type=getgrease2(&rnd,NULL,1,
					staticgrease,re->grease);
				rd=re->data;
				if(!((e->data=nd=
					malloc(sizeof(DATA)+rd->size))))
				{
					BAD("malloc failure\n");
					goto err2;
				}
				memset(nd->data,0,rd->size);
				nd->size=rd->size;
			}

			if(e)
			{
				*de=e;
				de=&(*de)->next;
			}

			continue;
		}

		if(!(*de=malloc(sizeof(EXTENSION))))
		{
			goto err1;
		}
		memset(*de,0,sizeof(EXTENSION));
		(*de)->type=re->type;

		switch(e->type)
		{
		case 0x000a:
			if(join_id2((ID2LIST **)&(*de)->data,
				(ID2LIST **)&e->data,re->data,0,&rnd,
				staticgrease,baseidx))
			{
				BAD2("extension %04x problem\n",e->type);
				goto err1;
			}
			break;

		case 0x000b:
			if(join_id1((ID1LIST **)&(*de)->data,
				(ID1LIST **)&e->data,re->data,&rnd,0,
				staticgrease))
			{
				BAD2("extension %04x problem\n",e->type);
				goto err1;
			}
			break;

		case 0x000d:
			if(join_id2((ID2LIST **)&(*de)->data,
				(ID2LIST **)&e->data,re->data,add,&rnd,
				staticgrease,-1))
			{
				BAD2("extension %04x problem\n",e->type);
				goto err1;
			}
			break;

		case 0x0010:
			if(join_alpn((LIST **)&(*de)->data,(LIST **)&e->data,
				re->data,&rnd,staticgrease))
			{
				BAD2("extension %04x problem\n",e->type);
				goto err1;
			}
			break;

		case 0x0033:
			if(join_list((LIST **)&(*de)->data,(LIST **)&e->data,
				re->data,&rnd,staticgrease,baseidx))
			{
				BAD2("extension %04x problem\n",e->type);
				goto err1;
			}
			break;

		case 0x002d:
			if(join_id1((ID1LIST **)&(*de)->data,
				(ID1LIST **)&e->data,re->data,&rnd,1,
				staticgrease))
			{
				BAD2("extension %04x problem\n",e->type);
				goto err1;
			}
			break;

		case 0x002b:
			if(join_id2((ID2LIST **)&(*de)->data,
				(ID2LIST **)&e->data,re->data,0,&rnd,
				staticgrease,-1))
			{
				BAD2("extension %04x problem\n",e->type);
				goto err1;
			}
			break;

		case 0x0015:
			((DATA *)(e->data))->size=0;
		default:(*de)->data=e->data;
			e->data=NULL;
			break;
		}

		de=&(*de)->next;
	}

	return 0;

err2:	free(e);
err1:	return -1;
}

CLIENTHELLO *new_clienthello(CLIENTHELLO *source)
{
	CLIENTHELLO *h;

	if(!(h=malloc(sizeof(CLIENTHELLO))))goto err1;
	memset(h,0,sizeof(CLIENTHELLO));
	memcpy(h->random,source->random,32);
	return h;

err1:	return NULL;
}

int modify_clienthellocipher(unsigned char *bfr,int len,int max,
	CLIENTHELLO *ref,int add,int staticgrease,unsigned char *random,
	int randlen)
{
	int i;
	int res=-1;
	ID2LIST *src=NULL;
	ID2LIST *dst=NULL;
	ID2LIST *e;
	ID2LIST **l2;
	RND rnd;

	rnd.random=random;
	rnd.len=randlen;
	rnd.pos=0;
	rnd.extmap=0;

	for(l2=&src,i=0;i<len;i+=2)
	{
		if(bfr[i]==bfr[i+1]&&(bfr[i]&0xf)==0xa)continue;
		if(!(*l2=e=malloc(sizeof(ID2LIST))))
		{
			BAD("malloc failure\n");
			goto err1;
		}
		e->next=NULL;
		memcpy(e->id,bfr+i,2);
		memset(e->grease,0,2);
		l2=&e->next;
	}

	if(join_id2(&dst,&src,ref->ciphersuite,add,&rnd,staticgrease,-1))
	{
		BAD("ciphersuite problem\n");
		goto err1;
	}

	for(res=0,e=dst;e&&res<max;e=e->next,res+=2)memcpy(bfr+res,e->id,2);

err1:	while(src)
	{
		e=src;
		src=e->next;
		free(e);
	}
	while(dst)
	{
		e=dst;
		dst=e->next;
		free(e);
	}
	return res;
}

int modify_clienthellocomp(unsigned char *bfr,int len,int max,CLIENTHELLO *ref,
	int staticgrease)
{
	int i;
	int res=-1;
	ID1LIST *src=NULL;
	ID1LIST *dst=NULL;
	ID1LIST *e;
	ID1LIST **l1;
	RND rnd;

	rnd.random=NULL;
	rnd.len=0;
	rnd.pos=0;
	rnd.extmap=0;

	for(l1=&src,i=0;i<len;i++)
	{
		if(!(*l1=e=malloc(sizeof(ID1LIST))))
		{
			BAD("malloc failure\n");
			goto err1;
		}
		e->next=NULL;
		e->id=bfr[i];
		e->grease=0;
		l1=&e->next;
	}

	if(join_id1(&dst,&src,ref->compmeth,&rnd,0,staticgrease))
	{
		BAD("compression method problem\n");
		goto err1;
	}

	for(res=0,e=dst;e&&res<max;e=e->next,res++)bfr[res]=e->id;

err1:	while(src)
	{
		e=src;
		src=e->next;
		free(e);
	}
	while(dst)
	{
		e=dst;
		dst=e->next;
		free(e);
	}
	return res;
}
