#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tlsdispatch.h"
#include "tlsclient.h"

#ifndef NO_EMU

#include "clientdata.h"
#include "clientloader.h"
#include "clientdissect.h"

#include "chromium_84_11.hh"
#include "chromium_84_12.hh"
#include "chromium_84_2.hh"
#include "chromium_84_31.hh"
#include "chromium_84_32.hh"
#include "firefox_78_1.hh"
#include "firefox_78_22.hh"
#include "firefox_78_23.hh"
#include "konqueror_50_1.hh"
#include "konqueror_50_2.hh"
#include "konqueror_50_31.hh"
#include "konqueror_50_32.hh"
#include "firefox_68a10_1.hh"
#include "firefox_68a10_22.hh"
#include "firefox_68a10_23.hh"
#include "firefox_68a10_31.hh"
#include "firefox_68a10_32.hh"
#include "kiwi_77a10_11.hh"
#include "kiwi_77a10_12.hh"
#include "kiwi_77a10_2.hh"
#include "kiwi_77a10_3.hh"
#include "firefox_79a10_1.hh"
#include "firefox_79a10_22.hh"
#include "firefox_79a10_23.hh"

#define ALPNENTRIES	2
#define MAXCHAIN	2
#define MAXSEQ		8

#define TEMPLATE(a)	{a,sizeof(a)-1}

typedef struct 
{
	const char *template;
	const int length;
} ENTRY;

typedef struct
{
	const int usealpn;
	const int emu;
	const int strict;
	const int loose;
	const int extra;
	const int abortver;
	const int canresume12[MAXSEQ+1];
	const int canresume13[MAXSEQ+1];
	const int retriesno[MAXSEQ+1];
	const int retries12[MAXSEQ+1];
	const int retries13[MAXSEQ+1];
	const ENTRY noresume[MAXCHAIN];
	const ENTRY resume12[MAXCHAIN];
	const ENTRY resume13[MAXCHAIN];
	const ENTRY conabort[MAXCHAIN];
} EMULATION;

static const int cannotresume[MAXSEQ+1];

static const EMULATION chromium_84=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{1,1,1,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{2,1,1,0,0,0,0,0,0},
	{2,1,1,0,0,0,0,0,0},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION brave_110=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{0,1,0,0,0,0,0,0,0},
	{0,1,0,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION chrome_84a10=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{2,1,1,0,0,0,0,0,0},
	{2,1,1,0,0,0,0,0,0},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION opera_59a10=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{0,1,0,0,0,0,0,0,0},
	{0,1,0,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION brave_111a10=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{1,1,0,0,0,0,0,0,0},
	{1,1,1,0,1,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{3,1,1,0,0,0,0,0,0},
	{1,1,1,1,1,0,0,0,0},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION vivaldi31a10=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{1,1,0,0,0,0,0,0,0},
	{0,1,1,0,1,0,0,0,0},
	{1,2,2,1,2,0,0,0,0},
	{2,1,1,0,0,0,0,0,0},
	{1,1,1,1,1,1,1,0,0},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION opera_69=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{1,1,0,0,0,0,0,0,0},
	{0,1,0,1,0,0,0,0,0},
	{1,1,1,2,2,0,0,0,0},
	{4,1,1,0,0,0,0,0,0},
	{1,1,1,1,1,1,1,1,1},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION opera_70=
{
	1,
	TLS_CLIENT_EMU_CHROMIUM_84_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{1,1,0,0,0,0,0,0,0},
	{0,1,0,1,0,0,0,0,0},
	{2,2,2,0,0,0,0,0,0},
	{4,1,1,0,0,0,0,0,0},
	{1,1,1,1,1,1,1,1,1},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_2)},
	{TEMPLATE(chromium_84_11),TEMPLATE(chromium_84_12)},
	{TEMPLATE(chromium_84_31),TEMPLATE(chromium_84_32)},
};

static const EMULATION firefox_78=
{
	1,
	TLS_CLIENT_EMU_FIREFOX_78_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{0,1,0,0,0,0,0,0,0},
	{0,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{TEMPLATE(firefox_78_1)},
	{TEMPLATE(firefox_78_22)},
	{TEMPLATE(firefox_78_23)},
};

static const EMULATION firefox_68a10=
{
	1,
	TLS_CLIENT_EMU_FIREFOX_68_ANDROID_10,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_FF68A10_RETRY,
	-1,
	{0,1,0,0,0,0,0,0,0},
	{0,1,0,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0},
	{TEMPLATE(firefox_68a10_1)},
	{TEMPLATE(firefox_68a10_22)},
	{TEMPLATE(firefox_68a10_23)},
	{TEMPLATE(firefox_68a10_31),TEMPLATE(firefox_68a10_32)},
};

static const EMULATION firefox_79a10=
{
	1,
	TLS_CLIENT_EMU_FIREFOX_78_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{0,1,0,0,0,0,0,0,0},
	{0,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{TEMPLATE(firefox_79a10_1)},
	{TEMPLATE(firefox_79a10_22)},
	{TEMPLATE(firefox_79a10_23)},
};

static const EMULATION konqueror_50=
{
	1,
	TLS_CLIENT_EMU_KONQUEROR_5_O_LINUX,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CERT_BROTLI,
	TLS_CLIENT_EMU_NO_OPTION,
	-1,
	{0,1,0,0,0,0,0,0,0},
	{0,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{TEMPLATE(konqueror_50_1)},
	{TEMPLATE(konqueror_50_2)},
	{TEMPLATE(konqueror_50_31),TEMPLATE(konqueror_50_32)},
};

static const EMULATION kiwi_77a10=
{
	1,
	TLS_CLIENT_EMU_KIWI_77_ANDROID_10,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_EMU_NO_CHANNEL_ID,
	TLS_CLIENT_EMU_NO_OPTION,
	TLS_CLIENT_TLS_1_2,
	{1,1,0,0,0,0,0,0,0},
	{1,1,0,0,0,0,0,0,0},
	{4,1,1,0,0,0,0,0,0},
	{2,1,1,0,0,0,0,0,0},
	{2,1,1,0,0,0,0,0,0},
	{TEMPLATE(kiwi_77a10_11),TEMPLATE(kiwi_77a10_12)},
	{TEMPLATE(kiwi_77a10_2)},
	{TEMPLATE(kiwi_77a10_11),TEMPLATE(kiwi_77a10_12)},
	{TEMPLATE(kiwi_77a10_3)},
};

static const char *alpndata[2]=
{
	"h2",
	"http/1.1"
};

static int loadtemplate(void *context,int group,const char *template,
	const int length)
{
	COMMON *cmn=*((COMMON **)context);
	CHAIN *ch;
	CHAIN *r;
	void *tmpl;
	FILE *fp;
	char bfr[8192];

	if(group<0||group>=MAXGROUPS)return -1;
	if(length>sizeof(bfr))return -1;
	memcpy(bfr,template,length);
	if(!(fp=fmemopen(bfr,length,"r")))return -1;
	if(!(tmpl=load_clienthello(NULL,fp)))return -1;
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
}

#endif

void *tls_client_emulation_init(int emulation,int strict)
{
#ifndef NO_EMU
	int i;
	int mode;
	const EMULATION *emu;
	void *cln;
	COMMON *cmn;

	switch(emulation)
	{
	case TLS_CLIENT_EMULATION_CHROMIUM_84_LINUX:
		emu=&chromium_84;
		break;
	case TLS_CLIENT_EMULATION_VIVALDI_31_ANDROID_10:
		emu=&vivaldi31a10;
		break;
	case TLS_CLIENT_EMULATION_OPERA_69_LINUX:
		emu=&opera_69;
		break;
	case TLS_CLIENT_EMULATION_OPERA_70_LINUX:
		emu=&opera_70;
		break;
	case TLS_CLIENT_EMULATION_FIREFOX_78_LINUX:
		emu=&firefox_78;
		break;
	case TLS_CLIENT_EMULATION_KONQUEROR_5_O_LINUX:
		emu=&konqueror_50;
		break;
	case TLS_CLIENT_EMULATION_FIREFOX_68_ANDROID_10:
		emu=&firefox_68a10;
		break;
	case TLS_CLIENT_EMULATION_KIWI_77_ANDROID_10:
		emu=&kiwi_77a10;
		break;
	case TLS_CLIENT_EMULATION_BRAVE_111_ANDROID_10:
		emu=&brave_111a10;
		break;
	case TLS_CLIENT_EMULATION_BRAVE_110_LINUX:
		emu=&brave_110;
		break;
	case TLS_CLIENT_EMULATION_OPERA_59_ANDROID_10:
		emu=&opera_59a10;
		break;
	case TLS_CLIENT_EMULATION_CHROME_84_ANDROID_10:
		emu=&chrome_84a10;
		break;
	case TLS_CLIENT_EMULATION_FIREFOX_79_ANDROID_10:
		emu=&firefox_79a10;
		break;

	default:goto err1;
	}

	switch(strict)
	{
	case TLS_CLIENT_EMULATION_LOOSE:
		mode=emu->loose;
		break;
	case TLS_CLIENT_EMULATION_STRICT:
		mode=emu->strict;
		break;
	default:goto err1;
	}

	if(!(cln=tls_client_init(emu->emu)))goto err1;

	cmn=*((COMMON **)cln);
	cmn->emumode=mode;
	cmn->emulation=emu;

	if(emu->usealpn)if(tls_client_set_alpn(cln,ALPNENTRIES,
		(char **)alpndata))goto err2;

	for(i=0;i<MAXCHAIN&&emu->noresume[i].template;i++)
		if(loadtemplate(cln,TLS_CLIENT_EMU_TEMPLATE_GROUP_1,
			emu->noresume[i].template,emu->noresume[i].length))
				goto err2;

	for(i=0;i<MAXCHAIN&&emu->resume12[i].template;i++)
		if(loadtemplate(cln,TLS_CLIENT_EMU_TEMPLATE_GROUP_2,
			emu->resume12[i].template,emu->resume12[i].length))
				goto err2;

	for(i=0;i<MAXCHAIN&&emu->resume13[i].template;i++)
		if(loadtemplate(cln,TLS_CLIENT_EMU_TEMPLATE_GROUP_3,
			emu->resume13[i].template,emu->resume13[i].length))
				goto err2;

	for(i=0;i<MAXCHAIN&&emu->conabort[i].template;i++)
		if(loadtemplate(cln,TLS_CLIENT_EMU_TEMPLATE_GROUP_4,
			emu->conabort[i].template,emu->conabort[i].length))
				goto err2;

	return cln;

err2:	tls_client_fini(cln);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *tls_client_emulation_connect(void *context,int timeout,char *host,
	int verify,void *resume,int *tlsver,char **alpn,
	int (*tcpconnect)(void *user),void *user)
{
#ifndef NO_EMU
	COMMON *cmn=*((COMMON **)context);
	const EMULATION *emu;
	void *con;
	void *doresume;
	const int *retries;
	const int *canresume;
	int i;
	int j;
	int k;
	int rcnt;
	int group;
	int fd;
	int mayresume;
	int vermem;
	unsigned int status;

	if(resume&&!tlsver)goto err1;
	if(!(emu=cmn->emulation))goto err1;

	if(resume)switch(*tlsver)
	{
	case TLS_CLIENT_TLS_1_3:
		group=TLS_CLIENT_EMU_TEMPLATE_GROUP_3;
		canresume=emu->canresume13;
		retries=emu->retries13;
		break;
	default:group=TLS_CLIENT_EMU_TEMPLATE_GROUP_2;
		canresume=emu->canresume12;
		retries=emu->retries12;
		break;
	}
	else
	{
		group=TLS_CLIENT_EMU_TEMPLATE_GROUP_1;
		canresume=cannotresume;
		retries=emu->retriesno;
	}

	if(resume)switch(group)
	{
	case TLS_CLIENT_EMU_TEMPLATE_GROUP_2:
		if(!emu->resume12[0].template)
		{
			group=TLS_CLIENT_EMU_TEMPLATE_GROUP_1;
			resume=NULL;
		}
		break;

	case TLS_CLIENT_EMU_TEMPLATE_GROUP_3:
		if(!emu->resume13[0].template)
		{
			group=TLS_CLIENT_EMU_TEMPLATE_GROUP_1;
			resume=NULL;
		}
		break;
	}

	for(k=0,mayresume=1,vermem=-1;k<retries[0];k++,mayresume=canresume[0])
		for(j=1;j<=MAXSEQ;j++)
	{
		if(!(j&1))
		{
			if(!emu->conabort[0].template)goto err2;

			if(emu->abortver!=-1)
			  if((vermem=tls_client_get_max_tls_version(context))
			    !=-1)
			      if(tls_client_set_max_tls_version(context,
				emu->abortver))goto err2;

			if(tls_client_use_hello_template(context,
				TLS_CLIENT_EMU_TEMPLATE_GROUP_4,
				cmn->emumode|emu->extra))goto err2;

		}
		else if(tls_client_use_hello_template(context,group,
			cmn->emumode))goto err2;

		if((rcnt=canresume[j])&&mayresume)doresume=resume;
		else doresume=NULL;

		for(i=0;i<retries[j];i++)
		{
			if((fd=tcpconnect(user))==-1)goto err2;

			con=tls_client_connect(context,fd,timeout,host,verify,
				doresume);
			status=tls_client_get_emulation_error();
			if(con&&(status&TLS_CLIENT_EMU_STATUS_MODIFY_ERROR))
				goto err3;
			if(con)goto ok;

			if(status&(TLS_CLIENT_EMU_STATUS_OPTION_ERROR|
				TLS_CLIENT_EMU_STATUS_MODIFY_ERROR|
				TLS_CLIENT_EMU_STATUS_TX_ERROR|
				TLS_CLIENT_EMU_STATUS_RX_ERROR))goto err2;

			if((status&TLS_CLIENT_EMU_STATUS_TX_COUNT)!=0x10)
				goto err2;

			if(rcnt)rcnt--;
			if(!rcnt)doresume=NULL;
		}

		if(vermem!=-1)
		{
			if(tls_client_set_max_tls_version(context,vermem))
				goto err1;
			vermem=-1;
		}
	}

	goto err2;

ok:	if(tlsver)*tlsver=tls_client_get_tls_version(con);
	if(alpn)*alpn=tls_client_get_alpn(con);

	return con;

err3:	tls_client_disconnect(con,NULL);
err2:	if(vermem!=-1)tls_client_set_max_tls_version(context,vermem);
err1:	return NULL;
#else
	return NULL;
#endif
}
