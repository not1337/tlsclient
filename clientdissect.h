/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _CLIENTDISSECT_H
#define _CLIENTDISSECT_H

extern CLIENTHELLO *dissect_clienthello(unsigned char *data,int len,int tlshdr,
	int grease,int asis);
extern int obfuscate_clienthello(unsigned char *data,int len);
extern void free_clienthello(CLIENTHELLO *h);
extern int find_psk_in_clienthello(unsigned char *data,int len);

#endif
