/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "clientdata.h"
#include "clientdump.h"
#include "clientdissect.h"
#include "clienttables.h"

#define OUTPUT(a,b)						\
do								\
{								\
	if(!b)printf("%s\n",a);					\
	else							\
	{							\
		DUMP *d;					\
		int l;						\
		l=strlen(a);					\
		if(!(d=malloc(sizeof(DUMP)+l+1)))goto fail;	\
		memcpy(d->data,a,l+1);				\
		d->len=l;					\
		d->next=NULL;					\
		*b=d;						\
		b=&d->next;					\
	}							\
} while(0)

static __thread char ebfr[64];

static char *lookup1(const struct id1 *tab,unsigned char data)
{
	int i;

	for(i=0;tab[i].name;i++)if(data==tab[i].id[0])
		return (char *)(tab[i].name);
	return NULL;
}

static char *lookup2(const struct id2 *tab,unsigned char *data)
{
	int i;

	for(i=0;tab[i].name;i++)if(!memcmp(data,tab[i].id,2))
		return (char *)(tab[i].name);
	return NULL;
}

static char *extlabel(EXTENSION *e,int mode)
{
	switch(e->type)
	{
	case 0x0000:
		return "extension-sni-hostname";
	case 0x0001:
		return "extension-max-fragment-length";
	case 0x0002:
		return "extension-client-certificate-url";
	case 0x0003:
		return "extension-trusted-ca-keys";
	case 0x0004:
		return "extension-truncated-hmac";
	case 0x0005:
		return "extension-status-request";
	case 0x0006:
		return "extension-user-mapping";
	case 0x0007:
		return "extension-client-authz";
	case 0x0008:
		return "extension-server-authz";
	case 0x0009:
		return "extension-cert-type";
	case 0x000a:
		return mode?"extension-supported-group":NULL;
	case 0x000b:
		return mode?"extension-ec-point-format":NULL;
	case 0x000c:
		return "extension-srp";
	case 0x000d:
		return mode?"extension-signature-algorithm":NULL;
	case 0x000e:
		return "extension-use-srtp";
	case 0x000f:
		return "extension-heartbeat";
	case 0x0010:
		return mode?"extension-alpn":NULL;
	case 0x0011:
		return "extension-status-request-v2";
	case 0x0012:
		return "extension-signed-certificate-timestamp";
	case 0x0013:
		return "extension-client-certificate-type";
	case 0x0014:
		return "extension-server-certificate-type";
	case 0x0015:
		return mode?"extension-padding":NULL;
	case 0x0016:
		return "extension-encrypt-then-mac";
	case 0x0017:
		return "extension-extended-master-secret";
	case 0x0018:
		return "extension-token-binding";
	case 0x0019:
		return "extension-cached-info";
	case 0x001a:
		return "extension-tls-lts";
	case 0x001b:
		return mode?"extension-compress-certificate":NULL;
	case 0x001c:
		return "extension-record-size-limit";
	case 0x001d:
		return "extension-pwd-protect";
	case 0x001e:
		return "extension-pwd-clear";
	case 0x001f:
		return "extension-password-salt";
	case 0x0020:
		return "extension-ticket-pinning";
	case 0x0021:
		return "extension-tls-cert-with-extern-psk";
	case 0x0022:
		return "extension-delegated-credentials";
	case 0x0023:
		return "extension-session-ticket";
	case 0x0027:
		return "extension-supported-ekt-ciphers";
	case 0x0029:
		return mode?"extension-pre-shared-key":NULL;
	case 0x002a:
		return "extension-early-data";
	case 0x002b:
		return mode?"extension-supported-version":NULL;
	case 0x002c:
		return "extension-cookie";
	case 0x002d:
		return mode?"extension-psk-key-exchange-mode":NULL;
	case 0x002f:
		return "extension-certificate-authorities";
	case 0x0030:
		return "extension-oid-filters";
	case 0x0031:
		return "extension-post-handshake-auth";
	case 0x0032:
		return "extension-signature-algorithms-cert";
	case 0x0033:
		return mode?"extension-key-share":NULL;
	case 0x0034:
		return "extension-transparency-info";
	case 0x0035:
		return "extension-connection-id";
	case 0x0037:
		return "extension-external-id-hash";
	case 0x0038:
		return "extension-external-session-id";
	case 0x0a0a:
		return "extension-grease";
	case 0x3374:
		return "extension-old-next-protocol-negotiation";
	case 0x3377:
		return "extension-origin-bound-certificates";
	case 0x337c:
		return "extension-encrypted-client-certificates";
	case 0x5500:
		return "extension-token-binding-test";
	case 0x754f:
		return "extension-old-channel-id";
	case 0x7550:
		return "extension-channel-id";
	case 0x8b47:
		return "extension-new-padding";
	case 0xff01:
		return "extension-renegotiation-info";
	case 0xff02:
		return "extension-tls-draft";
	case 0xff03:
		return "extension-short-header";
	default:sprintf(ebfr,"extension-UNKNOWN-%04x",e->type);
		return ebfr;
	}
}

static void diffdump(char *label,unsigned char *dl,int ls,unsigned char *dr,
	int rs)
{
	int i;
	int j;
	int k;
	char bfr[60];

	printf("Data Difference %s:\n",label);
	for(i=0,j=0;i<ls||j<rs;)
	{
		memset(bfr,' ',59);
		bfr[59]=0;
		for(k=0;k<8&&i<ls;k++,i++)
		{
			sprintf(bfr+3*k,"%02x",dl[i]);
			bfr[3*k+2]=' ';
		}
		bfr[24]='|';
		for(k=0;k<8&&j<rs;k++,j++)
		{
			sprintf(bfr+3*k+26,"%02x",dr[j]);
			bfr[3*k+28]=' ';
		}
		printf("%s\n",bfr);
	}
}

static void extdiff(int type,unsigned char *l,int ls,unsigned char *r,int rs)
{
	EXTENSION e;
	unsigned char *ll;
	unsigned char *rr;
	int lls;
	int rrs;
	int n;

	e.type=type;

	switch(type)
	{
	case 0x0033:
		if(!ls||!rs)
		{
			diffdump(extlabel(&e,1),l,ls,r,rs);
			break;
		}
		ll=l+2;
		lls=ls-2;
		rr=r+2;
		rrs=rs-2;
		while(lls&&rrs)
		{
			if(memcmp(ll,rr,2))break;
			n=ll[2];
			n<<=8;
			n+=ll[3];
			ll+=n+4;
			lls-=n+4;
			n=rr[2];
			n<<=8;
			n+=rr[3];
			rr+=n+4;
			rrs-=n+4;
		}
		if(lls||rrs)diffdump(extlabel(&e,1),l,ls,r,rs);
		break;
	case 0x0029:
		if((ls&&rs)||(!ls&&!rs))break;
	default:if(!l||!r)diffdump(extlabel(&e,1),l,ls,r,rs);
		else if(ls!=rs||memcmp(l,r,ls))
			diffdump(extlabel(&e,1),l,ls,r,rs);
		break;
	}
}

void dump_clienthello(CLIENTHELLO *h,int showgrease,DUMP **list,int loose)
{
	char *val;
	LIST *ll;
	ID1LIST *l1;
	ID2LIST *l2;
	EXTENSION *e;
	DUMP **work=list;
	char bfr[64];
	char str[256];

	if(loose)sprintf(str,"tls-length %d",h->tlslen>512?512:
		(h->tlslen>160?160:h->tlslen));
	else sprintf(str,"tls-length %d",h->tlslen);
	OUTPUT(str,work);

	if(!(val=lookup2(tlsver,h->envelopetls)))
	{
		sprintf(bfr,"UNKNOWN-%02x%02x",h->envelopetls[0],
			h->envelopetls[1]);
		val=bfr;
	}
	sprintf(str,"envelope-tls %s",val);
	OUTPUT(str,work);

	if(!(val=lookup2(tlsver,h->hellotls)))
	{
		sprintf(bfr,"UNKNOWN-%02x%02x",h->hellotls[0],h->hellotls[1]);
		val=bfr;
	}
	sprintf(str,"hello-tls %s",val);
	OUTPUT(str,work);

	if(h->sessionid)
	{
		sprintf(str,"session-id %d",h->sessionid->size);
		OUTPUT(str,work);
	}

	for(l2=h->ciphersuite;l2;l2=l2->next)
	{
		if(!memcmp(l2->id,"\x0a\x0a",2))
		{
			if(!showgrease)strcpy(bfr,"grease");
			else sprintf(bfr,"grease 0x%02x%02x",l2->grease[0],
				l2->grease[1]);
			val=bfr;
		}
		else if(!(val=lookup2(ciphersuites,l2->id)))
		{
			sprintf(bfr,"UNKNOWN-%02x%02x",l2->id[0],l2->id[1]);
			val=bfr;
		}
		sprintf(str,"ciphersuite %s",val);
		OUTPUT(str,work);
	}

	for(l1=h->compmeth;l1;l1=l1->next)
	{
		if(!(val=lookup1(compmeth,l1->id)))
		{
			sprintf(bfr,"UNKNOWN-%02x",l1->id);
			val=bfr;
		}
		sprintf(str,"compression-method %s",val);
		OUTPUT(str,work);
	}

	for(e=h->extension;e;e=e->next)switch(e->type)
	{
	case 0x0000:
		for(ll=e->data;ll;ll=ll->next)if(!ll->id)
			sprintf(str,"%s %s",extlabel(e,1),
				loose?"xxx":(char *)(ll->data));
		else sprintf(str,"extension-sni-UNKNOWN-%02x %d",ll->id,
			ll->size);
		OUTPUT(str,work);
		break;
	case 0x000a:
		for(l2=e->data;l2;l2=l2->next)
		{
			if(!memcmp(l2->id,"\x0a\x0a",2))
			{
				if(!showgrease)strcpy(bfr,"grease");
				else sprintf(bfr,"grease 0x%02x%02x",
					l2->grease[0],l2->grease[1]);
				val=bfr;
			}
			else if(!(val=lookup2(group,l2->id)))
			{
				sprintf(bfr,"UNKNOWN-%02x%02x",l2->id[0],
					l2->id[1]);
				val=bfr;
			}
			sprintf(str,"%s %s",extlabel(e,1),val);
			OUTPUT(str,work);
		}
		break;
	case 0x000b:
		for(l1=e->data;l1;l1=l1->next)
		{
			if(!(val=lookup1(ecpointformat,l1->id)))
			{
				sprintf(bfr,"UNKNOWN-%02x",l1->id);
				val=bfr;
			}
			sprintf(str,"%s %s",extlabel(e,1),val);
			OUTPUT(str,work);
		}
		break;
	case 0x0010:
		for(ll=e->data;ll;ll=ll->next)
		{
			if(ll->size==2&&!memcmp(ll->data,"\x0a\x0a",2))
			{
				if(!showgrease)strcpy(bfr,"grease");
				else sprintf(bfr,"grease 0x%02x%02x",
				ll->grease[0],ll->grease[1]);
				val=bfr;
			}
			else val=(char *)(ll->data);
			sprintf(str,"%s %s",extlabel(e,1),(char *)(ll->data));
			OUTPUT(str,work);
		}
		break;
	case 0x0005:
		ll=e->data;
		if(!(val=lookup1(statusrequest,ll->id)))
		{
			sprintf(bfr,"UNKNOWN-%02x",ll->id);
			val=bfr;
		}
		sprintf(str,"%s %s %d",extlabel(e,1),val,ll->size);
		OUTPUT(str,work);
		break;
	case 0x000d:
		for(l2=e->data;l2;l2=l2->next)
		{
			if(!memcmp(l2->id,"\x0a\x0a",2))
			{
				if(!showgrease)strcpy(bfr,"grease");
				else sprintf(bfr,"grease 0x%02x%02x",
					l2->grease[0],l2->grease[1]);
				val=bfr;
			}
			else if(!(val=lookup2(sigalg,l2->id)))
			{
				sprintf(bfr,"UNKNOWN-%02x%02x",l2->id[0],
					l2->id[1]);
				val=bfr;
			}
			sprintf(str,"%s %s",extlabel(e,1),val);
			OUTPUT(str,work);
		}
		break;
	case 0x0033:
		for(ll=e->data;ll;ll=ll->next)
		{
			bfr[0]=(unsigned char)(ll->id>>8);
			bfr[1]=(unsigned char)(ll->id);
			if(ll->id==0x0a0a)
			{
				if(!showgrease)strcpy(bfr,"grease");
				else sprintf(bfr,"grease 0x%02x%02x",
					ll->grease[0],ll->grease[1]);
				val=bfr;
			}
			else if(!(val=lookup2(group,(unsigned char *)bfr)))
			{
				sprintf(bfr,"UNKNOWN-%04x",ll->id);
				val=bfr;
			}
			sprintf(str,"%s %s %d",extlabel(e,1),val,ll->size);
			OUTPUT(str,work);
		}
		break;
	case 0x002d:
		for(l1=e->data;l1;l1=l1->next)
		{
			if(l1->id==0x0b)
			{
				if(!showgrease)strcpy(bfr,"grease");
				else sprintf(bfr,"grease 0x%02x",l1->grease);
				val=bfr;
			}
			else if(!(val=lookup1(pskkeyexchange,l1->id)))
			{
				sprintf(bfr,"UNKNOWN-%02x",l1->id);
				val=bfr;
			}
			sprintf(str,"%s %s",extlabel(e,1),val);
			OUTPUT(str,work);
		}
		break;
	case 0x002b:
		for(l2=e->data;l2;l2=l2->next)
		{
			if(!memcmp(l2->id,"\x0a\x0a",2))
			{
				if(!showgrease)strcpy(bfr,"grease");
				else sprintf(bfr,"grease 0x%02x%02x",
					l2->grease[0],l2->grease[1]);
				val=bfr;
			}
			else if(!(val=lookup2(tlsver,l2->id)))
			{
				sprintf(bfr,"UNKNOWN-%02x%02x",l2->id[0],
					l2->id[1]);
				val=bfr;
			}
			sprintf(str,"%s %s",extlabel(e,1),val);
			OUTPUT(str,work);
		}
		break;
	case 0x001b:
		for(l2=e->data;l2;l2=l2->next)
		{
			if(!(val=lookup2(compcert,l2->id)))
			{
				sprintf(bfr,"UNKNOWN-%02x%02x",l2->id[0],
					l2->id[1]);
				val=bfr;
			}
			sprintf(str,"%s %s",extlabel(e,1),val);
			OUTPUT(str,work);
		}
		break;
	case 0x001c:
		ll=e->data;
		sprintf(str,"%s %d %d",extlabel(e,1),ll->id,ll->size);
		OUTPUT(str,work);
		break;
	case 0x0a0a:
		if(!showgrease)sprintf(str,"%s %d",extlabel(e,1),
			((DATA *)(e->data))->size);
		else sprintf(str,"%s %d 0x%02x%02x",extlabel(e,1),
			((DATA *)(e->data))->size,e->grease[0],e->grease[1]);
		OUTPUT(str,work);
		break;
	case 0x0023:
		if(loose)sprintf(str,"%s %d",extlabel(e,1),
			((DATA *)(e->data))->size>100?100:
			((DATA *)(e->data))->size);
		else sprintf(str,"%s %d",extlabel(e,1),
			((DATA *)(e->data))->size);
		OUTPUT(str,work);
		break;
	case 0x0015:
		if(loose)
		{
			sprintf(str,"%s %d",extlabel(e,1),
				((DATA *)(e->data))->size>50?2:1);
			OUTPUT(str,work);
			break;
		}
	default:sprintf(str,"%s %d",extlabel(e,1),((DATA *)(e->data))->size);
		OUTPUT(str,work);
		break;
	}

	return;

fail:	while(*list)
	{
		DUMP *d=*list;
		*list=d->next;
		free(d);
	}
}

int diff_clienthello(CLIENTHELLO *left,CLIENTHELLO *right,int showgrease,
	int loose)
{
	int res=-1;
	int max;
	int gl;
	int gr;
	char *label;
	DUMP *l=NULL;
	DUMP *r=NULL;
	DUMP *e;
	DUMP *f;
	DUMP **ll;
	DUMP **rr;
	EXTENSION *ee;
	EXTENSION *ff;
	DATA *dl;
	DATA *dr;
	LIST *lll;
	LIST *rrr;

	dump_clienthello(left,showgrease,&l,loose);
	dump_clienthello(right,showgrease,&r,loose);

	if(!l||!r)goto fail;

	res=0;

	for(ll=&l;*ll;)
	{
		e=*ll;
		for(rr=&r;*rr;rr=&(*rr)->next)
		{
			f=*rr;
			if(e->len!=f->len)continue;
			if(!memcmp(e->data,f->data,e->len))break;
		}
		if(!*rr)
		{
			ll=&(*ll)->next;
			continue;
		}
		e=*rr;
		*rr=e->next;
		free(e);
		e=*ll;
		*ll=e->next;
		free(e);
	}

	for(max=0,e=l;e;e=e->next)if(e->len>max)max=e->len;

	for(e=l,f=r;e||f;)
	{
		res=1;
		printf("%*.*s | %s\n",max,max,e?e->data:"",f?f->data:"");
		if(e)e=e->next;
		if(f)f=f->next;
	}

	for(gl=0,ee=left->extension;ee;ee=ee->next)
	{
		if(!(label=extlabel(ee,0)))continue;
		if(ee->type==0x0a0a)gl++;
		for(gr=0,ff=right->extension;ff;ff=ff->next)
		{
			if(ff->type==ee->type)
			{
				if(ff->type!=0x0a0a)break;
				if(++gr==gl)break;
			}
		}
		if(!ff)continue;
		switch(ee->type)
		{
		case 0x0000:
			lll=ee->data;
			rrr=ff->data;
			if(!lll->id&&!rrr->id)break;
			if(lll->size==rrr->size&&
				!memcmp(lll->data,rrr->data,lll->size))break;
			diffdump(label,lll->data,lll->size,rrr->data,rrr->size);
			res=1;
			break;

		case 0x0005:
		case 0x001c:
			lll=ee->data;
			rrr=ff->data;
			if(lll->size==rrr->size&&
				!memcmp(lll->data,rrr->data,lll->size))break;
			diffdump(label,lll->data,lll->size,rrr->data,rrr->size);
			res=1;
			break;

		case 0x0023:
			dl=ee->data;
			dr=ff->data;
			if(dl->size==dr->size)break;
			if(loose&&dl->size&&dr->size)
			{
				if(dl->size>dr->size&&dl->size<=dr->size+64)
					break;
				if(dr->size>dl->size&&dr->size<=dl->size+64)
					break;
			}
			diffdump(label,dl->data,dl->size,dr->data,dr->size);
			res=1;
			break;

		default:dl=ee->data;
			dr=ff->data;
			if(dl->size==dr->size&&
				!memcmp(dl->data,dr->data,dl->size))break;
			diffdump(label,dl->data,dl->size,dr->data,dr->size);
			res=1;
			break;
		}
	}

fail:	while(l)
	{
		e=l;
		l=e->next;
		free(e);
	}
	while(r)
	{
		e=r;
		r=e->next;
		free(e);
	}
	return res;
}

int cmp_clienthello(unsigned char *left,int lsize,unsigned char *right,
	int rsize)
{
	int l;
	int n;
	int lt;
	int nt;
	CLIENTHELLO *unused;

	/* note: running dissect verifies data and changes grease values to
	   default ones, 0x0a0a for 2 byte and 0x0b for one byte */

	if(!(unused=dissect_clienthello(left,lsize,1,1,0)))
	{
		printf("bad input data (left)\n");
		return -1;
	}
	free_clienthello(unused);
	if(!(unused=dissect_clienthello(right,rsize,1,1,0)))
	{
		printf("bad input data (right)\n");
		return -1;
	}
	free_clienthello(unused);

	if(left[0]==0x14)
	{
		l=left[3];
		l<<=8;
		l+=left[4];
		left+=l+5;
		lsize-=l+5;
	}

	if(right[0]==0x14)
	{
		l=right[3];
		l<<=8;
		l+=right[4];
		right+=l+5;
		rsize-=l+5;
	}

	if(left[0]!=0x16||right[0]!=0x16)printf("unexpected internal error\n");

	if(memcmp(left+1,right+1,2))diffdump("envelope-tls",left+1,2,right+1,2);

	if(memcmp(left+3,right+3,2))diffdump("tls-length",left+3,2,right+3,2);

	left+=5;
	lsize-=5;
	right+=5;
	rsize-=5;

	if(left[0]!=0x01||right[0]!=0x01)printf("unexpected internal error\n");

	if(memcmp(left+4,right+4,2))diffdump("hello-tls",left+4,2,right+4,2);

	left+=38;
	lsize-=38;
	right+=38;
	rsize-=38;

	if(memcmp(left,right,1))diffdump("session-id",left,1,right,1);

	lsize-=left[0]+1;
	left+=left[0]+1;
	rsize-=right[0]+1;
	right+=right[0]+1;

	l=left[0];
	l<<=8;
	l+=left[1];
	n=right[0];
	n<<=8;
	n+=right[1];

	if(l!=n||memcmp(left+2,right+2,l))
		diffdump("ciphersuite",left+2,l,right+2,n);

	left+=l+2;
	lsize-=l+2;
	right+=n+2;
	rsize-=n+2;

	l=left[0];
	n=right[0];

	if(l!=n||memcmp(left+1,right+1,l))
		diffdump("compression-method",left+1,l,right+1,n);

	left+=l+3;
	lsize-=l+3;
	right+=n+3;
	rsize-=n+3;

	while(lsize>=4&&rsize>=4)
	{
		lt=left[0];
		lt<<=8;
		lt+=left[1];
		l=left[2];
		l<<=8;
		l+=left[3];
		nt=right[0];
		nt<<=8;
		nt+=right[1];
		n=right[2];
		n<<=8;
		n+=right[3];

		if(lt==nt)extdiff(lt,left+4,l,right+4,n);
		else
		{
			extdiff(lt,left+4,l,NULL,0);
			extdiff(nt,NULL,0,right+4,n);
		}

		left+=l+4;
		lsize-=l+4;
		right+=n+4;
		rsize-=n+4;
	}

	while(lsize>=4)
	{
		lt=left[0];
		lt<<=8;
		lt+=left[1];
		l=left[2];
		l<<=8;
		l+=left[3];

		extdiff(lt,left+4,l,NULL,0);

		left+=l+4;
		lsize-=l+4;
	}

	while(rsize>=4)
	{
		nt=right[0];
		nt<<=8;
		nt+=right[1];
		n=right[2];
		n<<=8;
		n+=right[3];

		extdiff(nt,NULL,0,right+4,n);

		right+=n+4;
		rsize-=n+4;
	}

	if(lsize||rsize)diffdump("surplus",left,lsize,right,rsize);

	return 0;
}
