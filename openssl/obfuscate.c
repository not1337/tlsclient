/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

static void usage(void)
{
	fprintf(stderr,"Usage: obfuscate -i infile -o outfile -f function "
		"-v version\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int c;
	int i;
	int l1;
	int l2;
	char *ptr;
	char *in=NULL;
	char *out=NULL;
	char *func=NULL;
	char *ver=NULL;
	FILE *ifp;
	FILE *ofp;
	unsigned char random[32];
	unsigned char obfusc[32];
	char r[256];
	char o[256];
	char bfr[1024];

	while((c=getopt(argc,argv,"i:o:f:v:"))!=-1)switch(c)
	{
	case 'i':
		in=optarg;
		break;
	case 'o':
		out=optarg;
		break;
	case 'f':
		func=optarg;
		break;
	case 'v':
		ver=optarg;
		break;
	default:usage();
	}

	if(argc!=optind||!in||!out||!func||!ver||strlen(func)+strlen(ver)>29)
		usage();

	if((c=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)
	{
		perror("open");
		return 1;
	}
	if(read(c,random,32)!=32)
	{
		perror("read");
		return 1;
	}
	close(c);

	l1=strlen(func)+1;
	l2=strlen(ver)+1;
	obfusc[0]=(unsigned char)l1;
	memcpy(obfusc+1,func,l1);
	memcpy(obfusc+1+l1,ver,l2);
	memset(obfusc+1+l1+l2,0xe2,32-l1-l2-1);
	for(c=0;c<32;c++)obfusc[c]^=random[c];
	strcpy(r,"\"");
	for(i=0,c=1;i<32;i++)c+=sprintf(r+c,"\\x%02x",random[i]);
	strcat(r,"\";\n");
	strcpy(o,"\"");
	for(i=0,c=1;i<32;i++)c+=sprintf(o+c,"\\x%02x",obfusc[i]);
	strcat(o,"\";\n");

	if(!(ifp=fopen(in,"re")))
	{
		perror("fopen");
		return 1;
	}
	if(!(ofp=fopen(out,"we")))
	{
		perror("fopen");
		return 1;
	}

	while(fgets(bfr,sizeof(bfr),ifp))
	{
		if((ptr=strstr(bfr,"__STR1__")))strcpy(ptr,r);
		else if((ptr=strstr(bfr,"__STR2__")))strcpy(ptr,o);
		fprintf(ofp,"%s",bfr);
	}

	fclose(ifp);
	fclose(ofp);

	return 0;
}
