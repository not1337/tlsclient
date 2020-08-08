/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _CLIENTDATA_H
#define _CLIENTDATA_H

typedef struct dump
{
	struct dump *next;
	int len;
	char data[0];
} DUMP;

typedef struct
{
	int size;
	unsigned char data[0];
} DATA;

typedef struct list
{
	struct list *next;
	int id;
	int size;
	unsigned char grease[2];
	unsigned char data[0];
} LIST;

typedef struct id2list
{
	struct id2list *next;
	unsigned char id[2];
	unsigned char grease[2];
} ID2LIST;

typedef struct id1list
{
	struct id1list *next;
	unsigned char id;
	unsigned char grease;
} ID1LIST;

typedef struct extension
{
	struct extension *next;
	void *data;
	int type;
	unsigned char grease[2];
} EXTENSION;

typedef struct
{
	int tlslen;
	unsigned char envelopetls[2];
	unsigned char hellotls[2];
	unsigned char random[32];
	DATA *sessionid;
	ID2LIST *ciphersuite;
	ID1LIST *compmeth;
	EXTENSION *extension;
} CLIENTHELLO;

#endif
