/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _CLIENTCONSTRUCT_H
#define _CLIENTCONSTRUCT_H

extern int modify_clienthello(CLIENTHELLO *dst,CLIENTHELLO *src,
	CLIENTHELLO *ref,int tlshdr,int add,int staticgrease,
	unsigned char *random,int randlen,int asis);
extern CLIENTHELLO *new_clienthello(CLIENTHELLO *source);
extern int modify_clienthellocipher(unsigned char *bfr,int len,int max,
	CLIENTHELLO *ref,int add,int staticgrease,unsigned char *random,
	int randlen);
extern int modify_clienthellocomp(unsigned char *bfr,int len,
	int max,CLIENTHELLO *ref,int staticgrease);

#endif
