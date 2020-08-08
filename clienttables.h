/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _CLIENTTABLES_H
#define _CLIENTTABLES_H

struct id1
{
	const unsigned char id[1];
	const char *name;
};

struct id2
{
	const unsigned char id[2];
	const char *name;
};

extern const struct id2 tlsver[];
extern const struct id2 ciphersuites[];
extern const struct id1 compmeth[];
extern const struct id2 group[];
extern const struct id1 ecpointformat[];
extern const struct id1 statusrequest[];
extern const struct id2 sigalg[];
extern const struct id1 pskkeyexchange[];
extern const struct id2 compcert[];

#endif
