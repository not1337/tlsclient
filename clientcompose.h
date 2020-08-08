/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _CLIENTCOMPOSE_H
#define _CLIENTCOMPOSE_H

extern int compose_clienthello(CLIENTHELLO *src,unsigned char *dst,int size,
	int tlshdr);

#endif
