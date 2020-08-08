/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <string.h>
#include "clientdata.h"
#include "clientcompose.h"

static int list1size(LIST *ll)
{
	int i;

	for(i=0;ll;ll=ll->next)i+=ll->size+1;
	return i;
}

static int list3size(LIST *ll)
{
	int i;

	for(i=0;ll;ll=ll->next)i+=ll->size+3;
	return i;
}

static int list4size(LIST *ll)
{
	int i;

	for(i=0;ll;ll=ll->next)i+=ll->size+4;
	return i;
}

static int id1size(ID1LIST *l1)
{
	int i;

	for(i=0;l1;l1=l1->next,i++);
	return i;
}

static int id2size(ID2LIST *l2)
{
	int i;

	for(i=0;l2;l2=l2->next,i+=2);
	return i;
}

static void list1insert(unsigned char *dst,LIST *ll)
{
	for(;ll;ll=ll->next)
	{
		*dst++=(unsigned char)(ll->size);
		memcpy(dst,ll->data,ll->size);
		dst+=ll->size;
	}
}

static void list3insert(unsigned char *dst,LIST *ll)
{
	for(;ll;ll=ll->next)
	{
		*dst++=(unsigned char)(ll->id);
		*dst++=(unsigned char)(ll->size>>8);
		*dst++=(unsigned char)(ll->size);
		memcpy(dst,ll->data,ll->size);
		dst+=ll->size;
	}
}

static void list4insert(unsigned char *dst,LIST *ll)
{
	for(;ll;ll=ll->next)
	{
		*dst++=(unsigned char)(ll->id>>8);
		*dst++=(unsigned char)(ll->id);
		*dst++=(unsigned char)(ll->size>>8);
		*dst++=(unsigned char)(ll->size);
		memcpy(dst,ll->data,ll->size);
		dst+=ll->size;
	}
}

static void id1insert(unsigned char *dst,ID1LIST *l1)
{
	for(;l1;l1=l1->next)*dst++=l1->id;
}

static void id2insert(unsigned char *dst,ID2LIST *l2)
{
	for(;l2;l2=l2->next,dst+=2)memcpy(dst,l2->id,2);
}

int compose_clienthello(CLIENTHELLO *src,unsigned char *dst,int size,int tlshdr)
{
	int i;
	int len;
	int val;
	int total=0;
	EXTENSION *e;
	unsigned char *lenpos[4]={NULL};

	if(tlshdr)
	{
		if(size<src->tlslen+5)return -1;
		dst[0]=0x16;
		memcpy(dst+1,src->envelopetls,2);
		lenpos[0]=dst+3;

		dst+=5;
		size-=5;
		total+=5;
	}
	else if(size<src->tlslen)return -1;

	if(size<38)return -1;
	dst[0]=0x01;
	lenpos[1]=dst+1;
	memcpy(dst+4,src->hellotls,2);
	memcpy(dst+6,src->random,32);

	dst+=38;
	size-=38;
	total+=38;

	if(src->sessionid)
	{
		if(size<src->sessionid->size+1)return -1;
		dst[0]=src->sessionid->size;
		memcpy(dst+1,src->sessionid->data,src->sessionid->size);

		dst+=src->sessionid->size+1;
		size-=src->sessionid->size+1;
		total+=src->sessionid->size+1;
	}
	else
	{
		dst[0]=0;
		dst+=1;
		size-=1;
		total+=1;
	}

	len=id2size(src->ciphersuite);
	if(size<len+2)return -1;
	dst[0]=(unsigned char)(len>>8);
	dst[1]=(unsigned char)(len);
	id2insert(dst+2,src->ciphersuite);

	dst+=len+2;
	size-=len+2;
	total+=len+2;

	len=id1size(src->compmeth);
	if(size<len+1)return -1;
	dst[0]=(unsigned char)len;
	id1insert(dst+1,src->compmeth);

	dst+=len+1;
	size-=len+1;
	total+=len+1;

	if(size<2)return -1;
	lenpos[2]=dst;

	dst+=2;
	size-=2;
	total+=2;

	for(lenpos[3]=NULL,e=src->extension;e;e=e->next)switch(e->type)
	{
	case 0x0005:
		len=((LIST *)(e->data))->size;
		if(size<len+5)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+1)>>8);
		dst[3]=(unsigned char)(len+1);
		dst[4]=(unsigned char)(((LIST *)(e->data))->id);
		memcpy(dst+5,((LIST *)(e->data))->data,len);
		dst+=len+5;
		size-=len+5;
		total+=len+5;
		break;

	case 0x0000:
		len=list3size(e->data);
		if(size<len+6)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+2)>>8);
		dst[3]=(unsigned char)(len+2);
		dst[4]=(unsigned char)(len>>8);
		dst[5]=(unsigned char)(len);
		list3insert(dst+6,e->data);
		dst+=len+6;
		size-=len+6;
		total+=len+6;
		break;

	case 0x0010:
		len=list1size(e->data);
		if(size<len+6)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+2)>>8);
		dst[3]=(unsigned char)(len+2);
		dst[4]=(unsigned char)(len>>8);
		dst[5]=(unsigned char)(len);
		list1insert(dst+6,e->data);
		dst+=len+6;
		size-=len+6;
		total+=len+6;
		break;

	case 0x0033:
		len=list4size(e->data);
		if(size<len+6)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+2)>>8);
		dst[3]=(unsigned char)(len+2);
		dst[4]=(unsigned char)(len>>8);
		dst[5]=(unsigned char)(len);
		list4insert(dst+6,e->data);
		dst+=len+6;
		size-=len+6;
		total+=len+6;
		break;

	case 0x002d:
	case 0x000b:
		len=id1size(e->data);
		if(size<len+5)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+1)>>8);
		dst[3]=(unsigned char)(len+1);
		dst[4]=(unsigned char)(len);
		id1insert(dst+5,e->data);
		dst+=len+5;
		size-=len+5;
		total+=len+5;
		break;

	case 0x001b:
		len=id2size(e->data);
		if(size<len+5)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+1)>>8);
		dst[3]=(unsigned char)(len+1);
		dst[4]=(unsigned char)(len);
		id2insert(dst+5,e->data);
		dst+=len+5;
		size-=len+5;
		total+=len+5;
		break;

	case 0x002b:
		len=id2size(e->data);
		if(size<len+5)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+1)>>8);
		dst[3]=(unsigned char)(len+1);
		dst[4]=(unsigned char)(len);
		id2insert(dst+5,e->data);
		dst+=len+5;
		size-=len+5;
		total+=len+5;
		break;

	case 0x000d:
	case 0x000a:
		len=id2size(e->data);
		if(size<len+6)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)((len+2)>>8);
		dst[3]=(unsigned char)(len+2);
		dst[4]=(unsigned char)(len>>8);
		dst[5]=(unsigned char)(len);
		id2insert(dst+6,e->data);
		dst+=len+6;
		size-=len+6;
		total+=len+6;
		break;

	case 0x001c:
		val=((LIST *)(e->data))->id;
		len=((LIST *)(e->data))->size;
		if(size<len+4)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)(len>>8);
		dst[3]=(unsigned char)(len);
		for(i=0;i<len;i++)
		{
			dst[3+len-i]=(unsigned char)(val);
			val>>=8;
		}
		dst+=len+4;
		size-=len+4;
		total+=len+4;
		break;

	case 0x0015:
		lenpos[3]=dst+2;
		goto cmn;
	default:lenpos[3]=NULL;
cmn:		len=((DATA *)(e->data))->size;
		if(size<len+4)return -1;
		dst[0]=(unsigned char)(e->type>>8);
		dst[1]=(unsigned char)(e->type);
		dst[2]=(unsigned char)(len>>8);
		dst[3]=(unsigned char)(len);
		memcpy(dst+4,((DATA *)(e->data))->data,len);
		dst+=len+4;
		size-=len+4;
		total+=len+4;
		break;
	}

	if(total<src->tlslen+(tlshdr?5:0)&&lenpos[3])
	{
		len=src->tlslen+(tlshdr?5:0)-total;
		memmove(lenpos[3]+2+len,lenpos[3]+2,len);
		memset(lenpos[3]+2,0,len);
		lenpos[3][0]=(unsigned char)(len>>8);
		lenpos[3][1]=(unsigned char)(len);

		dst+=len;
		size-=len;
		total+=len;
	}

	len=dst-lenpos[2];
	len-=2;
	lenpos[2][0]=(unsigned char)(len>>8);
	lenpos[2][1]=(unsigned char)(len);

	len=dst-lenpos[1];
	len-=3;
	lenpos[1][0]=(unsigned char)(len>>16);
	lenpos[1][1]=(unsigned char)(len>>8);
	lenpos[1][2]=(unsigned char)(len);

	if(tlshdr)
	{
		len=dst-lenpos[0];
		len-=2;
		lenpos[0][0]=(unsigned char)(len>>8);
		lenpos[0][1]=(unsigned char)(len);
	}

	return total;
}
