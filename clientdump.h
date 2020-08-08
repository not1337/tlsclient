/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _CLIENTDUMP_H
#define _CLIENTDUMP_H

extern void dump_clienthello(CLIENTHELLO *h,int showgrease,DUMP **list,
	int loose);
extern int diff_clienthello(CLIENTHELLO *left,CLIENTHELLO *right,
	int showgrease,int loose);
extern int cmp_clienthello(unsigned char *left,int lsize,unsigned char *right,
	int rsize);

#endif
