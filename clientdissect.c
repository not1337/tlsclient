/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <string.h>
#include <stdlib.h>
#include "clientdata.h"
#include "clientdissect.h"

static int isgrease1(unsigned char *data)
{
	switch(*data)
	{
	case 0x0B:
	case 0x2A:
	case 0x49:
	case 0x68:
	case 0x87:
	case 0xA6:
	case 0xC5:
	case 0xE4:
		return 1;
	default:return 0;
	}
}

static int isgrease2(unsigned char *data)
{
	if(data[0]==data[1]&&(data[0]&0xf)==0xa)return 1;
	return 0;
}

static int dissect_recsizelim(unsigned char *data,int len,void **anchor)
{
	int i;
	unsigned int size;
	LIST *ll;

	if(!len)return -1;
	for(size=0,i=0;i<len;i++)
	{
		if(size&0xff000000)return -1;
		size<<=8;
		size+=data[i];
	}
	if(size>65535)return -1;
	if(*anchor)return -1;
	if(!(*anchor=ll=malloc(sizeof(LIST)+len)))return -1;
	ll->next=NULL;
	ll->id=size;
	ll->size=len;
	memcpy(ll->data,data,len);
	memset(ll->grease,0,2);
	return 0;
}

static int dissect_sni(unsigned char *data,int len,void **anchor)
{
	int l;
	LIST *ll=NULL;

	if(len<2)return -1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if(len<l+2)return -1;
	data+=2;
	len=l;
	while(len)
	{
		if(len<3)return -1;
		l=data[1];
		l<<=8;
		l+=data[2];
		if(len<l+3)return -1;
		if(ll)
		{
			if(!(ll->next=malloc(sizeof(LIST)+l+1)))return -1;
			ll=ll->next;
		}
		else
		{
			if(!(ll=malloc(sizeof(LIST)+l+1)))return -1;
			*anchor=ll;
		}
		ll->next=NULL;
		ll->id=data[0];
		ll->size=l;
		memcpy(ll->data,data+3,l);
		ll->data[l]=0;
		memset(ll->grease,0,2);
		data+=l+3;
		len-=l+3;
	}
	return 0;
}

static int dissect_suppgroups(unsigned char *data,int len,void **anchor,int g)
{
	int i;
	int l;
	ID2LIST *l2=NULL;
	unsigned char grease[2];

	if((len&1)||len<2)return -1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if((l&1)||len<l+2)return -1;
	for(i=0;i<l;i+=2)
	{
		if(isgrease2(data+i+2))
		{
			if(!g)continue;
			memcpy(grease,data+i+2,2);
			data[i+2]=0x0a;
			data[i+3]=0x0a;
		}
		else memset(grease,0,2);
		if(l2)
		{
			if(!(l2->next=malloc(sizeof(ID2LIST))))return -1;
			l2=l2->next;
		}
		else
		{
			if(!(l2=malloc(sizeof(ID2LIST))))return -1;
			*anchor=l2;
		}
		l2->next=NULL;
		memcpy(l2->id,data+i+2,2);
		memcpy(l2->grease,grease,2);
	}
	return 0;
}

static int dissect_ecpointformat(unsigned char *data,int len,void **anchor)
{
	int i;
	int l;
	ID1LIST *l1=NULL;

	if(!len)return -1;
	l=data[0];
	if(len<l+1)return -1;
	for(i=0;i<l;i++)
	{
		if(l1)
		{
			if(!(l1->next=malloc(sizeof(ID1LIST))))return -1;
			l1=l1->next;
		}
		else
		{
			if(!(l1=malloc(sizeof(ID1LIST))))return -1;
			*anchor=l1;
		}
		l1->next=NULL;
		l1->id=data[i+1];
		l1->grease=0;
	}
	return 0;
}

static int dissect_alpn(unsigned char *data,int len,void **anchor,int g)
{
	int l;
	LIST *ll=NULL;
	unsigned char grease[2];

	if(len<2)return -1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if(len<l+2)return -1;
	data+=2;
	len=l;
	while(len)
	{
		l=data[0];
		if(len<l+1)return -1;
		if(l==2&&isgrease2(data+1))
		{
			if(!g)goto skip;
			memcpy(grease,data+1,2);
			data[1]=0x0a;
			data[2]=0x0a;
		}
		else memset(grease,0,2);
		if(ll)
		{
			if(!(ll->next=malloc(sizeof(LIST)+l+1)))return -1;
			ll=ll->next;
		}
		else
		{
			if(!(ll=malloc(sizeof(LIST)+l+1)))return -1;
			*anchor=ll;
		}
		ll->next=NULL;
		ll->size=l;
		ll->id=0;
		memcpy(ll->data,data+1,l);
		ll->data[l]=0;
		memcpy(ll->grease,grease,2);
skip:		data+=l+1;
		len-=l+1;
	}
	return 0;
}

static int dissect_statusrequest(unsigned char *data,int len,void **anchor)
{
	LIST *ll;

	if(!len)return -1;
	if(*anchor)return -1;
	if(!(*anchor=ll=malloc(sizeof(LIST)+len-1)))return -1;
	ll->next=NULL;
	ll->id=data[0];
	ll->size=len-1;
	memcpy(ll->data,data+1,len-1);
	memset(ll->grease,0,2);
	return 0;
}

static int dissect_sigalg(unsigned char *data,int len,void **anchor,int g)
{
	int i;
	int l;
	ID2LIST *l2=NULL;
	unsigned char grease[2];

	if((len&1)||len<2)return -1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if(len<l+2||(l&1))return -1;
	for(i=0;i<l;i+=2)
	{
		if(isgrease2(data+i+2))
		{
			if(!g)continue;
			memcpy(grease,data+i+2,2);
			data[i+2]=0x0a;
			data[i+3]=0x0a;
		}
		else memset(grease,0,2);
		if(l2)
		{
			if(!(l2->next=malloc(sizeof(ID2LIST))))return -1;
			l2=l2->next;
		}
		else
		{
			if(!(l2=malloc(sizeof(ID2LIST))))return -1;
			*anchor=l2;
		}
		l2->next=NULL;
		memcpy(l2->id,data+i+2,2);
		memcpy(l2->grease,grease,2);
	}
	return 0;
}

static int dissect_key_share(unsigned char *data,int len,void **anchor,int g)
{
	int l;
	LIST *ll=NULL;
	unsigned char grease[2];

	if(len<2)return -1;
	l=data[0];
	l<<=1;
	l+=data[1];
	if(len<l+2)return -1;
	data+=2;
	len=l;
	while(len)
	{
		if(len<4)return -1;
		l=data[2];
		l<<=8;
		l+=data[3];
		if(len<l+4)return -1;
		if(isgrease2(data))
		{
			if(!g)goto skip;
			memcpy(grease,data,2);
			data[0]=0x0a;
			data[1]=0x0a;
		}
		else memset(grease,0,2);
		if(ll)
		{
			if(!(ll->next=malloc(sizeof(LIST)+l)))return -1;
			ll=ll->next;
		}
		else
		{
			if(!(ll=malloc(sizeof(LIST)+l)))return -1;
			*anchor=ll;
		}
		ll->next=NULL;
		ll->id=data[0];
		ll->id<<=8;
		ll->id+=data[1];
		ll->size=l;
		memcpy(ll->data,data+4,l);
		memcpy(ll->grease,grease,2);
skip:		data+=l+4;
		len-=l+4;
	}
	return 0;
}

static int dissect_pskkexmode(unsigned char *data,int len,void **anchor,int g)
{
	int i;
	ID1LIST *l1=NULL;
	unsigned char grease;

	if(!len||data[0]!=len-1)return -1;
	data++;
	len--;
	for(i=0;i<len;i++)
	{
		if(isgrease1(data+i))
		{
			if(!g)continue;
			grease=data[i];
			data[i]=0x0b;
		}
		else grease=0;
		if(l1)
		{
			if(!(l1->next=malloc(sizeof(ID1LIST))))return -1;
			l1=l1->next;
		}
		else
		{
			if(!(l1=malloc(sizeof(ID1LIST))))return -1;
			*anchor=l1;
		}
		l1->next=NULL;
		l1->id=data[i];
		l1->grease=grease;
	}
	return 0;
}

static int dissect_suppver(unsigned char *data,int len,void **anchor,int g)
{
	int i;
	ID2LIST *l2=NULL;
	unsigned char grease[2];

	if(!len||data[0]!=len-1)return -1;
	data++;
	len--;
	if(len&1)return -1;
	for(i=0;i<len;i+=2)
	{
		if(isgrease2(data+i))
		{
			if(!g)continue;
			memcpy(grease,data+i,2);
			data[i]=0x0a;
			data[i+1]=0x0a;
		}
		else memset(grease,0,2);
		if(l2)
		{
			if(!(l2->next=malloc(sizeof(ID2LIST))))return -1;
			l2=l2->next;
		}
		else
		{
			if(!(l2=malloc(sizeof(ID2LIST))))return -1;
			*anchor=l2;
		}
		l2->next=NULL;
		memcpy(l2->id,data+i,2);
		memcpy(l2->grease,grease,2);
	}
	return 0;
}

static int dissect_compcert(unsigned char *data,int len,void **anchor)
{
	int i;
	int l;
	ID2LIST *l2=NULL;

	if(!len)return -1;
	l=data[0];
	if(len<l+1)return +1;
	data++;
	len=l;
	for(i=0;i<len;i+=2)
	{
		if(l2)
		{
			if(!(l2->next=malloc(sizeof(ID2LIST))))return -1;
			l2=l2->next;
		}
		else
		{
			if(!(l2=malloc(sizeof(ID2LIST))))return -1;
			*anchor=l2;
		}
		l2->next=NULL;
		memcpy(l2->id,data+i,2);
		memset(l2->grease,0,2);
	}
	return 0;
}

static int dissect_extensions(unsigned char *data,int len,CLIENTHELLO *h,int g)
{
	int l;
	int ext;
	EXTENSION *e=NULL;
	unsigned char grease[2];
	while(len)
	{
		if(len<4)return -1;
		ext=data[0];
		ext<<=8;
		ext|=data[1];
		l=data[2];
		l<<=8;
		l+=data[3];
		if(len<l+4)return -1;
		if(isgrease2(data))
		{
			if(!g)goto skip;
			memcpy(grease,data,2);
			data[0]=0x0a;
			data[1]=0x0a;
			ext=0x0a0a;
		}
		else memset(grease,0,2);
		if(e)
		{
			if(!(e->next=malloc(sizeof(EXTENSION))))return -1;
			e=e->next;
		}
		else
		{
			if(!(e=malloc(sizeof(EXTENSION))))return -1;
			h->extension=e;
		}
		e->next=NULL;
		e->data=NULL;
		memcpy(e->grease,grease,2);
		e->type=ext;
		switch(ext)
		{
		case 0x0000:
			if(dissect_sni(data+4,l,&e->data))return -1;
			break;
		case 0x000a:
			if(dissect_suppgroups(data+4,l,&e->data,g))return -1;
			break;
		case 0x000b:
			if(dissect_ecpointformat(data+4,l,&e->data))return -1;
			break;
		case 0x0010:
			if(dissect_alpn(data+4,l,&e->data,g))return -1;
			break;
		case 0x0005:
			if(dissect_statusrequest(data+4,l,&e->data))return -1;
			break;
		case 0x000d:
			if(dissect_sigalg(data+4,l,&e->data,g))return -1;
			break;
		case 0x0033:
			if(dissect_key_share(data+4,l,&e->data,g))return -1;
			break;
		case 0x002d:
			if(dissect_pskkexmode(data+4,l,&e->data,g))return -1;
			break;
		case 0x002b:
			if(dissect_suppver(data+4,l,&e->data,g))return -1;
			break;
		case 0x001b:
			if(dissect_compcert(data+4,l,&e->data))return -1;
			break;
		case 0x001c:
			if(dissect_recsizelim(data+4,l,&e->data))return -1;
			break;
		default:if(!(e->data=malloc(sizeof(DATA)+l)))return -1;
			((DATA *)(e->data))->size=l;
			memcpy(((DATA *)(e->data))->data,data+4,l);
			break;
		}
skip:		len-=l+4;
		data+=l+4;
	}
	return 0;
}

static int dissect_compression_methods(unsigned char *data,int len,
	CLIENTHELLO *h)
{
	int i;
	ID1LIST *l1=NULL;

	for(i=0;i<len;i++)
	{
		if(l1)
		{
			if(!(l1->next=malloc(sizeof(ID1LIST))))return -1;
			l1=l1->next;
		}
		else
		{
			if(!(l1=malloc(sizeof(ID2LIST))))return -1;
			h->compmeth=l1;
		}
		l1->next=NULL;
		l1->id=data[i];
		l1->grease=0;
	}
	return 0;
}

static int dissect_ciphersuites(unsigned char *data,int len,CLIENTHELLO *h,
	int g)
{
	int i;
	ID2LIST *l2=NULL;
	unsigned char grease[2];

	if(len&1)return -1;
	for(i=0;i<len;i+=2)
	{
		if(isgrease2(data+i))
		{
			if(!g)continue;
			if(g==2)memset(grease,0,2);
			else
			{
				memcpy(grease,data+i,2);
				data[i]=0x0a;
				data[i+1]=0x0a;
			}
		}
		else memset(grease,0,2);
		if(l2)
		{
			if(!(l2->next=malloc(sizeof(ID2LIST))))return -1;
			l2=l2->next;
		}
		else
		{
			if(!(l2=malloc(sizeof(ID2LIST))))return -1;
			h->ciphersuite=l2;
		}
		l2->next=NULL;
		memcpy(l2->id,data+i,2);
		memcpy(l2->grease,grease,2);
	}
	return 0;
}

static int dissect_hello_data(unsigned char *data,int len,CLIENTHELLO *h,int g,
	int asis)
{
	int l;
	int r;

	if(!len)return -1;
	l=data[0];
	if(len<l+1)return -1;
	if(!(h->sessionid=malloc(sizeof(DATA)+l)))return -1;
	h->sessionid->size=l;
	memcpy(h->sessionid->data,data+1,l);
	data+=l+1;
	len-=l+1;
	if(len<2)return -1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if(len<2+l)return -1;
	if((r=dissect_ciphersuites(data+2,l,h,asis?2:g)))return r;
	data+=l+2;
	len-=l-2;
	if(!len)return -1;
	l=data[0];
	if(len<l+1)return -1;
	if((r=dissect_compression_methods(data+1,l,h)))return r;
	data+=l+1;
	len-=l-1;
	if(len<2)return -1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if(len<2+l)return -1;
	return dissect_extensions(data+2,l,h,g);
}

static int dissect_hello(unsigned char *data,int len,CLIENTHELLO *h,int g,int m,
	int asis)
{
	int l;

	if(len<38)return -1;
	if(m)
	{
		if(data[0]!=0x01)return -2;
		l=data[1];
		l<<=8;
		l+=data[2];
		l<<=8;
		l+=data[3];
		if(l<len-4)return -1;
	}
	else l=len-4;
	memcpy(h->hellotls,data+4,2);
	memcpy(h->random,data+6,32);
	return dissect_hello_data(data+38,l-34,h,g,asis);
}

void free_clienthello(CLIENTHELLO *h)
{
	ID1LIST *l1;
	ID2LIST *l2;
	EXTENSION *e;
	LIST *ll;

	if(h->sessionid)free(h->sessionid);
	while(h->ciphersuite)
	{
		l2=h->ciphersuite;
		h->ciphersuite=l2->next;
		free(l2);
	}
	while(h->compmeth)
	{
		l1=h->compmeth;
		h->compmeth=l1->next;
		free(l1);
	}
	while(h->extension)
	{
		e=h->extension;
		h->extension=e->next;
		switch(e->type)
		{
		case 0x0010:
		case 0x0033:
		case 0x001c:
		case 0x0000:
		case 0x0005:
			while(e->data)
			{
				ll=e->data;
				e->data=ll->next;
				free(ll);
			}
			break;
		case 0x000b:
		case 0x002d:
			while(e->data)
			{
				l1=e->data;
				e->data=l1->next;
				free(l1);
			}
			break;
		case 0x000a:
		case 0x000d:
		case 0x002b:
		case 0x001b:
			while(e->data)
			{
				l2=e->data;
				e->data=l2->next;
				free(l2);
			}
			break;
		default:if(e->data)free(e->data);
			break;
		}
		free(e);
	}
	free(h);
}

CLIENTHELLO *dissect_clienthello(unsigned char *data,int len,int tlshdr,
	int grease,int asis)
{
	CLIENTHELLO *h;
	int l;

	if(!(h=malloc(sizeof(CLIENTHELLO))))goto err1;
	memset(h,0,sizeof(CLIENTHELLO));

	if(tlshdr<=0)
	{
		if(!dissect_hello(data,len,h,grease,tlshdr+1,asis))return h;
		goto err3;
	}

	if(len<5)goto err2;
	if(data[0]==0x14)
	{
		l=data[3];
		l<<=8;
		l+=data[4];
		if(l!=1||data[5]!=0x01)goto err1;
		if(len<l+5)goto err2;
		data+=l+5;
		len-=l+5;
	}
	if(len<5)goto err2;
	if(data[0]!=0x16)goto err2;
	memcpy(h->envelopetls,data+1,2);
	l=data[3];
	l<<=8;
	l+=data[4];
	if(l<len-5)goto err2;
	h->tlslen=l;
	if(!dissect_hello(data+5,l,h,grease,1,asis))return h;

	free_clienthello(h);
	return NULL;

err3:	free_clienthello(h);
err2:	free(h);
err1:	return NULL;
}


int obfuscate_clienthello(unsigned char *data,int len)
{
	int l;
	int ll;
	int tot;
	int ext;
	unsigned char *ptr;

	if(len<5)goto err1;
	if(data[0]==0x14)
	{
		l=data[3];
		l<<=8;
		l+=data[4];
		if(l!=1||data[5]!=0x01)goto err1;
		if(len<l+5)goto err1;
		data+=l+5;
		len-=l+5;
	}
	if(len<5)goto err1;
	if(data[0]!=0x16)goto err1;
	l=data[3];
	l<<=8;
	l+=data[4];
	if(l<len-5)goto err1;
	data+=5;
	len=l;

	if(len<38)goto err1;
	if(data[0]!=0x01)goto err1;
	l=data[1];
	l<<=8;
	l+=data[2];
	l<<=8;
	l+=data[3];
	if(l<len-4)goto err1;
	else l=len-4;
	data+=38;
	len=l-34;

	if(!len)goto err1;
	l=data[0];
	if(len<l+1)goto err1;
	data+=l+1;
	len-=l+1;
	if(len<2)goto err1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if(len<2+l)goto err1;
	data+=l+2;
	len-=l-2;
	if(!len)goto err1;
	l=data[0];
	if(len<l+1)goto err1;
	data+=l+1;
	len-=l-1;
	if(len<2)goto err1;
	l=data[0];
	l<<=8;
	l+=data[1];
	if(len<2+l)goto err1;
	data+=2;
	len=l;

	while(len)
	{
		if(len<4)return -1;
		ext=data[0];
		ext<<=8;
		ext|=data[1];
		l=data[2];
		l<<=8;
		l+=data[3];

		if(ext==0x0000)
		{
			ptr=data+4;
			if(l<2)goto err1;
			ll=ptr[0];
			ll<<=8;
			ll+=ptr[1];
			if(l<ll+2)goto err1;
			ptr+=2;
			tot=ll;
			while(tot)
			{
				if(tot<3)goto err1;
				ll=ptr[1];
				ll<<=8;
				ll+=ptr[2];
				if(tot<ll+3)goto err1;
				if(!ptr[0])memset(ptr+3,'x',ll);
				ptr+=ll+3;
				tot-=ll+3;
			}
		}

		len-=l+4;
		data+=l+4;
	}

	return 0;

err1:	return -1;
}

int find_psk_in_clienthello(unsigned char *data,int len)
{
	int pos;
	int l;
	int type;
	unsigned char *base=data;

	pos=data[38]+39;
	pos+=(data[pos]<<8)+data[pos+1]+2;
	pos+=data[pos]+1;
	l=(data[pos]<<8)+data[pos+1];
	pos+=2;
	if(pos+l>len)return 0;
	data+=pos;
	len=l;
	while(len>=4)
	{
		pos=0;
		type=data[0];
		type<<=8;
		type|=data[1];
		l=data[2];
		l<<=8;
		l|=data[3];
		if(type==0x0029&&l)pos=data-base;
		data+=l+4;
		len-=l+4;
	}
	return pos;
}
