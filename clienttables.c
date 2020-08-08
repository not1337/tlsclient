/*
 * This file is part of the tlsclient project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <stddef.h>
#include "clienttables.h"

const struct id2 tlsver[]=
{
	{{0x03,0x01},"TLS-1.0"},
	{{0x03,0x02},"TLS-1.1"},
	{{0x03,0x03},"TLS-1.2"},
	{{0x03,0x04},"TLS-1.3"},
	{{0x00,0x00},NULL},
};

const struct id2 ciphersuites[]=
{
	{{0x00,0x00},"TLS-NULL-WITH-NULL-NULL"},
	{{0x00,0x01},"TLS-RSA-WITH-NULL-MD5"},
	{{0x00,0x02},"TLS-RSA-WITH-NULL-SHA"},
	{{0x00,0x03},"TLS-RSA-EXPORT-WITH-RC4-40-MD5"},
	{{0x00,0x04},"TLS-RSA-WITH-RC4-128-MD5"},
	{{0x00,0x05},"TLS-RSA-WITH-RC4-128-SHA"},
	{{0x00,0x06},"TLS-RSA-EXPORT-WITH-RC2-CBC-40-MD5"},
	{{0x00,0x07},"TLS-RSA-WITH-IDEA-CBC-SHA"},
	{{0x00,0x08},"TLS-RSA-EXPORT-WITH-DES40-CBC-SHA"},
	{{0x00,0x09},"TLS-RSA-WITH-DES-CBC-SHA"},
	{{0x00,0x0A},"TLS-RSA-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x0B},"TLS-DH-DSS-EXPORT-WITH-DES40-CBC-SHA"},
	{{0x00,0x0C},"TLS-DH-DSS-WITH-DES-CBC-SHA"},
	{{0x00,0x0D},"TLS-DH-DSS-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x0E},"TLS-DH-RSA-EXPORT-WITH-DES40-CBC-SHA"},
	{{0x00,0x0F},"TLS-DH-RSA-WITH-DES-CBC-SHA"},
	{{0x00,0x10},"TLS-DH-RSA-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x11},"TLS-DHE-DSS-EXPORT-WITH-DES40-CBC-SHA"},
	{{0x00,0x12},"TLS-DHE-DSS-WITH-DES-CBC-SHA"},
	{{0x00,0x13},"TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x14},"TLS-DHE-RSA-EXPORT-WITH-DES40-CBC-SHA"},
	{{0x00,0x15},"TLS-DHE-RSA-WITH-DES-CBC-SHA"},
	{{0x00,0x16},"TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x17},"TLS-DH-anon-EXPORT-WITH-RC4-40-MD5"},
	{{0x00,0x18},"TLS-DH-anon-WITH-RC4-128-MD5"},
	{{0x00,0x19},"TLS-DH-anon-EXPORT-WITH-DES40-CBC-SHA"},
	{{0x00,0x1A},"TLS-DH-anon-WITH-DES-CBC-SHA"},
	{{0x00,0x1B},"TLS-DH-anon-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x1E},"TLS-KRB5-WITH-DES-CBC-SHA"},
	{{0x00,0x1F},"TLS-KRB5-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x20},"TLS-KRB5-WITH-RC4-128-SHA"},
	{{0x00,0x21},"TLS-KRB5-WITH-IDEA-CBC-SHA"},
	{{0x00,0x22},"TLS-KRB5-WITH-DES-CBC-MD5"},
	{{0x00,0x23},"TLS-KRB5-WITH-3DES-EDE-CBC-MD5"},
	{{0x00,0x24},"TLS-KRB5-WITH-RC4-128-MD5"},
	{{0x00,0x25},"TLS-KRB5-WITH-IDEA-CBC-MD5"},
	{{0x00,0x26},"TLS-KRB5-EXPORT-WITH-DES-CBC-40-SHA"},
	{{0x00,0x27},"TLS-KRB5-EXPORT-WITH-RC2-CBC-40-SHA"},
	{{0x00,0x28},"TLS-KRB5-EXPORT-WITH-RC4-40-SHA"},
	{{0x00,0x29},"TLS-KRB5-EXPORT-WITH-DES-CBC-40-MD5"},
	{{0x00,0x2A},"TLS-KRB5-EXPORT-WITH-RC2-CBC-40-MD5"},
	{{0x00,0x2B},"TLS-KRB5-EXPORT-WITH-RC4-40-MD5"},
	{{0x00,0x2C},"TLS-PSK-WITH-NULL-SHA"},
	{{0x00,0x2D},"TLS-DHE-PSK-WITH-NULL-SHA"},
	{{0x00,0x2E},"TLS-RSA-PSK-WITH-NULL-SHA"},
	{{0x00,0x2F},"TLS-RSA-WITH-AES-128-CBC-SHA"},
	{{0x00,0x30},"TLS-DH-DSS-WITH-AES-128-CBC-SHA"},
	{{0x00,0x31},"TLS-DH-RSA-WITH-AES-128-CBC-SHA"},
	{{0x00,0x32},"TLS-DHE-DSS-WITH-AES-128-CBC-SHA"},
	{{0x00,0x33},"TLS-DHE-RSA-WITH-AES-128-CBC-SHA"},
	{{0x00,0x34},"TLS-DH-anon-WITH-AES-128-CBC-SHA"},
	{{0x00,0x35},"TLS-RSA-WITH-AES-256-CBC-SHA"},
	{{0x00,0x36},"TLS-DH-DSS-WITH-AES-256-CBC-SHA"},
	{{0x00,0x37},"TLS-DH-RSA-WITH-AES-256-CBC-SHA"},
	{{0x00,0x38},"TLS-DHE-DSS-WITH-AES-256-CBC-SHA"},
	{{0x00,0x39},"TLS-DHE-RSA-WITH-AES-256-CBC-SHA"},
	{{0x00,0x3A},"TLS-DH-anon-WITH-AES-256-CBC-SHA"},
	{{0x00,0x3B},"TLS-RSA-WITH-NULL-SHA256"},
	{{0x00,0x3C},"TLS-RSA-WITH-AES-128-CBC-SHA256"},
	{{0x00,0x3D},"TLS-RSA-WITH-AES-256-CBC-SHA256"},
	{{0x00,0x3E},"TLS-DH-DSS-WITH-AES-128-CBC-SHA256"},
	{{0x00,0x3F},"TLS-DH-RSA-WITH-AES-128-CBC-SHA256"},
	{{0x00,0x40},"TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"},
	{{0x00,0x41},"TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"},
	{{0x00,0x42},"TLS-DH-DSS-WITH-CAMELLIA-128-CBC-SHA"},
	{{0x00,0x43},"TLS-DH-RSA-WITH-CAMELLIA-128-CBC-SHA"},
	{{0x00,0x44},"TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"},
	{{0x00,0x45},"TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
	{{0x00,0x46},"TLS-DH-anon-WITH-CAMELLIA-128-CBC-SHA"},
	{{0x00,0x67},"TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"},
	{{0x00,0x68},"TLS-DH-DSS-WITH-AES-256-CBC-SHA256"},
	{{0x00,0x69},"TLS-DH-RSA-WITH-AES-256-CBC-SHA256"},
	{{0x00,0x6A},"TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"},
	{{0x00,0x6B},"TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"},
	{{0x00,0x6C},"TLS-DH-anon-WITH-AES-128-CBC-SHA256"},
	{{0x00,0x6D},"TLS-DH-anon-WITH-AES-256-CBC-SHA256"},
	{{0x00,0x84},"TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"},
	{{0x00,0x85},"TLS-DH-DSS-WITH-CAMELLIA-256-CBC-SHA"},
	{{0x00,0x86},"TLS-DH-RSA-WITH-CAMELLIA-256-CBC-SHA"},
	{{0x00,0x87},"TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"},
	{{0x00,0x88},"TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
	{{0x00,0x89},"TLS-DH-anon-WITH-CAMELLIA-256-CBC-SHA"},
	{{0x00,0x8A},"TLS-PSK-WITH-RC4-128-SHA"},
	{{0x00,0x8B},"TLS-PSK-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x8C},"TLS-PSK-WITH-AES-128-CBC-SHA"},
	{{0x00,0x8D},"TLS-PSK-WITH-AES-256-CBC-SHA"},
	{{0x00,0x8E},"TLS-DHE-PSK-WITH-RC4-128-SHA"},
	{{0x00,0x8F},"TLS-DHE-PSK-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x90},"TLS-DHE-PSK-WITH-AES-128-CBC-SHA"},
	{{0x00,0x91},"TLS-DHE-PSK-WITH-AES-256-CBC-SHA"},
	{{0x00,0x92},"TLS-RSA-PSK-WITH-RC4-128-SHA"},
	{{0x00,0x93},"TLS-RSA-PSK-WITH-3DES-EDE-CBC-SHA"},
	{{0x00,0x94},"TLS-RSA-PSK-WITH-AES-128-CBC-SHA"},
	{{0x00,0x95},"TLS-RSA-PSK-WITH-AES-256-CBC-SHA"},
	{{0x00,0x96},"TLS-RSA-WITH-SEED-CBC-SHA"},
	{{0x00,0x97},"TLS-DH-DSS-WITH-SEED-CBC-SHA"},
	{{0x00,0x98},"TLS-DH-RSA-WITH-SEED-CBC-SHA"},
	{{0x00,0x99},"TLS-DHE-DSS-WITH-SEED-CBC-SHA"},
	{{0x00,0x9A},"TLS-DHE-RSA-WITH-SEED-CBC-SHA"},
	{{0x00,0x9B},"TLS-DH-anon-WITH-SEED-CBC-SHA"},
	{{0x00,0x9C},"TLS-RSA-WITH-AES-128-GCM-SHA256"},
	{{0x00,0x9D},"TLS-RSA-WITH-AES-256-GCM-SHA384"},
	{{0x00,0x9E},"TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"},
	{{0x00,0x9F},"TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xA0},"TLS-DH-RSA-WITH-AES-128-GCM-SHA256"},
	{{0x00,0xA1},"TLS-DH-RSA-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xA2},"TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"},
	{{0x00,0xA3},"TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xA4},"TLS-DH-DSS-WITH-AES-128-GCM-SHA256"},
	{{0x00,0xA5},"TLS-DH-DSS-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xA6},"TLS-DH-anon-WITH-AES-128-GCM-SHA256"},
	{{0x00,0xA7},"TLS-DH-anon-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xA8},"TLS-PSK-WITH-AES-128-GCM-SHA256"},
	{{0x00,0xA9},"TLS-PSK-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xAA},"TLS-DHE-PSK-WITH-AES-128-GCM-SHA256"},
	{{0x00,0xAB},"TLS-DHE-PSK-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xAC},"TLS-RSA-PSK-WITH-AES-128-GCM-SHA256"},
	{{0x00,0xAD},"TLS-RSA-PSK-WITH-AES-256-GCM-SHA384"},
	{{0x00,0xAE},"TLS-PSK-WITH-AES-128-CBC-SHA256"},
	{{0x00,0xAF},"TLS-PSK-WITH-AES-256-CBC-SHA384"},
	{{0x00,0xB0},"TLS-PSK-WITH-NULL-SHA256"},
	{{0x00,0xB1},"TLS-PSK-WITH-NULL-SHA384"},
	{{0x00,0xB2},"TLS-DHE-PSK-WITH-AES-128-CBC-SHA256"},
	{{0x00,0xB3},"TLS-DHE-PSK-WITH-AES-256-CBC-SHA384"},
	{{0x00,0xB4},"TLS-DHE-PSK-WITH-NULL-SHA256"},
	{{0x00,0xB5},"TLS-DHE-PSK-WITH-NULL-SHA384"},
	{{0x00,0xB6},"TLS-RSA-PSK-WITH-AES-128-CBC-SHA256"},
	{{0x00,0xB7},"TLS-RSA-PSK-WITH-AES-256-CBC-SHA384"},
	{{0x00,0xB8},"TLS-RSA-PSK-WITH-NULL-SHA256"},
	{{0x00,0xB9},"TLS-RSA-PSK-WITH-NULL-SHA384"},
	{{0x00,0xBA},"TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0x00,0xBB},"TLS-DH-DSS-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0x00,0xBC},"TLS-DH-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0x00,0xBD},"TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0x00,0xBE},"TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0x00,0xBF},"TLS-DH-anon-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0x00,0xC0},"TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{{0x00,0xC1},"TLS-DH-DSS-WITH-CAMELLIA-256-CBC-SHA256"},
	{{0x00,0xC2},"TLS-DH-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{{0x00,0xC3},"TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256"},
	{{0x00,0xC4},"TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
	{{0x00,0xC5},"TLS-DH-anon-WITH-CAMELLIA-256-CBC-SHA256"},
	{{0x00,0xC6},"TLS-SM4-GCM-SM3"},
	{{0x00,0xC7},"TLS-SM4-CCM-SM3"},
	{{0x00,0xFF},"TLS-EMPTY-RENEGOTIATION-INFO-SCSV"},
	{{0x13,0x01},"TLS-AES-128-GCM-SHA256"},
	{{0x13,0x02},"TLS-AES-256-GCM-SHA384"},
	{{0x13,0x03},"TLS-CHACHA20-POLY1305-SHA256"},
	{{0x13,0x04},"TLS-AES-128-CCM-SHA256"},
	{{0x13,0x05},"TLS-AES-128-CCM-8-SHA256"},
	{{0x56,0x00},"TLS-FALLBACK-SCSV"},
	{{0xC0,0x01},"TLS-ECDH-ECDSA-WITH-NULL-SHA"},
	{{0xC0,0x02},"TLS-ECDH-ECDSA-WITH-RC4-128-SHA"},
	{{0xC0,0x03},"TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x04},"TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x05},"TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x06},"TLS-ECDHE-ECDSA-WITH-NULL-SHA"},
	{{0xC0,0x07},"TLS-ECDHE-ECDSA-WITH-RC4-128-SHA"},
	{{0xC0,0x08},"TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x09},"TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x0A},"TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x0B},"TLS-ECDH-RSA-WITH-NULL-SHA"},
	{{0xC0,0x0C},"TLS-ECDH-RSA-WITH-RC4-128-SHA"},
	{{0xC0,0x0D},"TLS-ECDH-RSA-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x0E},"TLS-ECDH-RSA-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x0F},"TLS-ECDH-RSA-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x10},"TLS-ECDHE-RSA-WITH-NULL-SHA"},
	{{0xC0,0x11},"TLS-ECDHE-RSA-WITH-RC4-128-SHA"},
	{{0xC0,0x12},"TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x13},"TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x14},"TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x15},"TLS-ECDH-anon-WITH-NULL-SHA"},
	{{0xC0,0x16},"TLS-ECDH-anon-WITH-RC4-128-SHA"},
	{{0xC0,0x17},"TLS-ECDH-anon-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x18},"TLS-ECDH-anon-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x19},"TLS-ECDH-anon-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x1A},"TLS-SRP-SHA-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x1B},"TLS-SRP-SHA-RSA-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x1C},"TLS-SRP-SHA-DSS-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x1D},"TLS-SRP-SHA-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x1E},"TLS-SRP-SHA-RSA-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x1F},"TLS-SRP-SHA-DSS-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x20},"TLS-SRP-SHA-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x21},"TLS-SRP-SHA-RSA-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x22},"TLS-SRP-SHA-DSS-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x23},"TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"},
	{{0xC0,0x24},"TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"},
	{{0xC0,0x25},"TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256"},
	{{0xC0,0x26},"TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384"},
	{{0xC0,0x27},"TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"},
	{{0xC0,0x28},"TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"},
	{{0xC0,0x29},"TLS-ECDH-RSA-WITH-AES-128-CBC-SHA256"},
	{{0xC0,0x2A},"TLS-ECDH-RSA-WITH-AES-256-CBC-SHA384"},
	{{0xC0,0x2B},"TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"},
	{{0xC0,0x2C},"TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"},
	{{0xC0,0x2D},"TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256"},
	{{0xC0,0x2E},"TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384"},
	{{0xC0,0x2F},"TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"},
	{{0xC0,0x30},"TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"},
	{{0xC0,0x31},"TLS-ECDH-RSA-WITH-AES-128-GCM-SHA256"},
	{{0xC0,0x32},"TLS-ECDH-RSA-WITH-AES-256-GCM-SHA384"},
	{{0xC0,0x33},"TLS-ECDHE-PSK-WITH-RC4-128-SHA"},
	{{0xC0,0x34},"TLS-ECDHE-PSK-WITH-3DES-EDE-CBC-SHA"},
	{{0xC0,0x35},"TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA"},
	{{0xC0,0x36},"TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA"},
	{{0xC0,0x37},"TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256"},
	{{0xC0,0x38},"TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA384"},
	{{0xC0,0x39},"TLS-ECDHE-PSK-WITH-NULL-SHA"},
	{{0xC0,0x3A},"TLS-ECDHE-PSK-WITH-NULL-SHA256"},
	{{0xC0,0x3B},"TLS-ECDHE-PSK-WITH-NULL-SHA384"},
	{{0xC0,0x3C},"TLS-RSA-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x3D},"TLS-RSA-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x3E},"TLS-DH-DSS-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x3F},"TLS-DH-DSS-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x40},"TLS-DH-RSA-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x41},"TLS-DH-RSA-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x42},"TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x43},"TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x44},"TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x45},"TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x46},"TLS-DH-anon-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x47},"TLS-DH-anon-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x48},"TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x49},"TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x4A},"TLS-ECDH-ECDSA-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x4B},"TLS-ECDH-ECDSA-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x4C},"TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x4D},"TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x4E},"TLS-ECDH-RSA-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x4F},"TLS-ECDH-RSA-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x50},"TLS-RSA-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x51},"TLS-RSA-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x52},"TLS-DHE-RSA-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x53},"TLS-DHE-RSA-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x54},"TLS-DH-RSA-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x55},"TLS-DH-RSA-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x56},"TLS-DHE-DSS-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x57},"TLS-DHE-DSS-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x58},"TLS-DH-DSS-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x59},"TLS-DH-DSS-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x5A},"TLS-DH-anon-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x5B},"TLS-DH-anon-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x5C},"TLS-ECDHE-ECDSA-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x5D},"TLS-ECDHE-ECDSA-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x5E},"TLS-ECDH-ECDSA-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x5F},"TLS-ECDH-ECDSA-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x60},"TLS-ECDHE-RSA-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x61},"TLS-ECDHE-RSA-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x62},"TLS-ECDH-RSA-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x63},"TLS-ECDH-RSA-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x64},"TLS-PSK-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x65},"TLS-PSK-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x66},"TLS-DHE-PSK-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x67},"TLS-DHE-PSK-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x68},"TLS-RSA-PSK-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x69},"TLS-RSA-PSK-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x6A},"TLS-PSK-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x6B},"TLS-PSK-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x6C},"TLS-DHE-PSK-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x6D},"TLS-DHE-PSK-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x6E},"TLS-RSA-PSK-WITH-ARIA-128-GCM-SHA256"},
	{{0xC0,0x6F},"TLS-RSA-PSK-WITH-ARIA-256-GCM-SHA384"},
	{{0xC0,0x70},"TLS-ECDHE-PSK-WITH-ARIA-128-CBC-SHA256"},
	{{0xC0,0x71},"TLS-ECDHE-PSK-WITH-ARIA-256-CBC-SHA384"},
	{{0xC0,0x72},"TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x73},"TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x74},"TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x75},"TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x76},"TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x77},"TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x78},"TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x79},"TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x7A},"TLS-RSA-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x7B},"TLS-RSA-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x7C},"TLS-DHE-RSA-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x7D},"TLS-DHE-RSA-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x7E},"TLS-DH-RSA-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x7F},"TLS-DH-RSA-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x80},"TLS-DHE-DSS-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x81},"TLS-DHE-DSS-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x82},"TLS-DH-DSS-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x83},"TLS-DH-DSS-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x84},"TLS-DH-anon-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x85},"TLS-DH-anon-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x86},"TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x87},"TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x88},"TLS-ECDH-ECDSA-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x89},"TLS-ECDH-ECDSA-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x8A},"TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x8B},"TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x8C},"TLS-ECDH-RSA-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x8D},"TLS-ECDH-RSA-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x8E},"TLS-PSK-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x8F},"TLS-PSK-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x90},"TLS-DHE-PSK-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x91},"TLS-DHE-PSK-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x92},"TLS-RSA-PSK-WITH-CAMELLIA-128-GCM-SHA256"},
	{{0xC0,0x93},"TLS-RSA-PSK-WITH-CAMELLIA-256-GCM-SHA384"},
	{{0xC0,0x94},"TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x95},"TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x96},"TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x97},"TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x98},"TLS-RSA-PSK-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x99},"TLS-RSA-PSK-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x9A},"TLS-ECDHE-PSK-WITH-CAMELLIA-128-CBC-SHA256"},
	{{0xC0,0x9B},"TLS-ECDHE-PSK-WITH-CAMELLIA-256-CBC-SHA384"},
	{{0xC0,0x9C},"TLS-RSA-WITH-AES-128-CCM"},
	{{0xC0,0x9D},"TLS-RSA-WITH-AES-256-CCM"},
	{{0xC0,0x9E},"TLS-DHE-RSA-WITH-AES-128-CCM"},
	{{0xC0,0x9F},"TLS-DHE-RSA-WITH-AES-256-CCM"},
	{{0xC0,0xA0},"TLS-RSA-WITH-AES-128-CCM-8"},
	{{0xC0,0xA1},"TLS-RSA-WITH-AES-256-CCM-8"},
	{{0xC0,0xA2},"TLS-DHE-RSA-WITH-AES-128-CCM-8"},
	{{0xC0,0xA3},"TLS-DHE-RSA-WITH-AES-256-CCM-8"},
	{{0xC0,0xA4},"TLS-PSK-WITH-AES-128-CCM"},
	{{0xC0,0xA5},"TLS-PSK-WITH-AES-256-CCM"},
	{{0xC0,0xA6},"TLS-DHE-PSK-WITH-AES-128-CCM"},
	{{0xC0,0xA7},"TLS-DHE-PSK-WITH-AES-256-CCM"},
	{{0xC0,0xA8},"TLS-PSK-WITH-AES-128-CCM-8"},
	{{0xC0,0xA9},"TLS-PSK-WITH-AES-256-CCM-8"},
	{{0xC0,0xAA},"TLS-PSK-DHE-WITH-AES-128-CCM-8"},
	{{0xC0,0xAB},"TLS-PSK-DHE-WITH-AES-256-CCM-8"},
	{{0xC0,0xAC},"TLS-ECDHE-ECDSA-WITH-AES-128-CCM"},
	{{0xC0,0xAD},"TLS-ECDHE-ECDSA-WITH-AES-256-CCM"},
	{{0xC0,0xAE},"TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8"},
	{{0xC0,0xAF},"TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8"},
	{{0xC0,0xB0},"TLS-ECCPWD-WITH-AES-128-GCM-SHA256"},
	{{0xC0,0xB1},"TLS-ECCPWD-WITH-AES-256-GCM-SHA384"},
	{{0xC0,0xB2},"TLS-ECCPWD-WITH-AES-128-CCM-SHA256"},
	{{0xC0,0xB3},"TLS-ECCPWD-WITH-AES-256-CCM-SHA384"},
	{{0xC0,0xB4},"TLS-SHA256-SHA256"},
	{{0xC0,0xB5},"TLS-SHA384-SHA384"},
	{{0xC1,0x00},"TLS-GOSTR341112-256-WITH-KUZNYECHIK-CTR-OMAC"},
	{{0xC1,0x01},"TLS-GOSTR341112-256-WITH-MAGMA-CTR-OMAC"},
	{{0xC1,0x02},"TLS-GOSTR341112-256-WITH-28147-CNT-IMIT"},
	{{0xC1,0x03},"TLS-GOSTR341112-256-WITH-KUZNYECHIK-MGM-L"},
	{{0xC1,0x04},"TLS-GOSTR341112-256-WITH-MAGMA-MGM-L"},
	{{0xC1,0x05},"TLS-GOSTR341112-256-WITH-KUZNYECHIK-MGM-S"},
	{{0xC1,0x06},"TLS-GOSTR341112-256-WITH-MAGMA-MGM-S"},
	{{0xCC,0xA8},"TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
	{{0xCC,0xA9},"TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
	{{0xCC,0xAA},"TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
	{{0xCC,0xAB},"TLS-PSK-WITH-CHACHA20-POLY1305-SHA256"},
	{{0xCC,0xAC},"TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256"},
	{{0xCC,0xAD},"TLS-DHE-PSK-WITH-CHACHA20-POLY1305-SHA256"},
	{{0xCC,0xAE},"TLS-RSA-PSK-WITH-CHACHA20-POLY1305-SHA256"},
	{{0xD0,0x01},"TLS-ECDHE-PSK-WITH-AES-128-GCM-SHA256"},
	{{0xD0,0x02},"TLS-ECDHE-PSK-WITH-AES-256-GCM-SHA384"},
	{{0xD0,0x03},"TLS-ECDHE-PSK-WITH-AES-128-CCM-8-SHA256"},
	{{0xD0,0x05},"TLS-ECDHE-PSK-WITH-AES-128-CCM-SHA256"},
	{{0x00,0x00},NULL},
};

const struct id1 compmeth[]=
{
	{{0x00},"NULL"},
	{{0x01},"DEFLATE"},
	{{0x40},"LZS"},
	{{0x00},NULL},
};

const struct id2 group[]=
{
	{{0x00,0x01},"SECT163K1"},
	{{0x00,0x02},"SECT163R1"},
	{{0x00,0x03},"SECT163R2"},
	{{0x00,0x04},"SECT193R1"},
	{{0x00,0x05},"SECT193R2"},
	{{0x00,0x06},"SECT233K1"},
	{{0x00,0x07},"SECT233R1"},
	{{0x00,0x08},"SECT239K1"},
	{{0x00,0x09},"SECT283K1"},
	{{0x00,0x0A},"SECT283R1"},
	{{0x00,0x0B},"SECT409K1"},
	{{0x00,0x0C},"SECT409R1"},
	{{0x00,0x0D},"SECT571K1"},
	{{0x00,0x0E},"SECT571R1"},
	{{0x00,0x0F},"SECP160K1"},
	{{0x00,0x10},"SECP160R1"},
	{{0x00,0x11},"SECP160R2"},
	{{0x00,0x12},"SECP192K1"},
	{{0x00,0x13},"SECP192R1"},
	{{0x00,0x14},"SECP224K1"},
	{{0x00,0x15},"SECP224R1"},
	{{0x00,0x16},"SECP256K1"},
	{{0x00,0x17},"SECP256R1"},
	{{0x00,0x18},"SECP384R1"},
	{{0x00,0x19},"SECP521R1"},
	{{0x00,0x1A},"BRAINPOOLP256R1"},
	{{0x00,0x1B},"BRAINPOOLP384R1"},
	{{0x00,0x1C},"BRAINPOOLP512R1"},
	{{0x00,0x1D},"X25519"},
	{{0x00,0x1E},"X448"},
	{{0x00,0x1F},"BRAINPOOLP256R1TLS13"},
	{{0x00,0x20},"BRAINPOOLP384R1TLS13"},
	{{0x00,0x21},"BRAINPOOLP512R1TLS13"},
	{{0x00,0x22},"GC256A"},
	{{0x00,0x23},"GC256B"},
	{{0x00,0x24},"GC256C"},
	{{0x00,0x25},"GC256D"},
	{{0x00,0x26},"GC512A"},
	{{0x00,0x27},"GC512B"},
	{{0x00,0x28},"GC512C"},
	{{0x00,0x29},"CURVESM2"},
	{{0x01,0x00},"FFDHE2048"},
	{{0x01,0x01},"FFDHE3072"},
	{{0x01,0x02},"FFDHE4096"},
	{{0x01,0x03},"FFDHE6144"},
	{{0x01,0x04},"FFDHE8192"},
	{{0xFF,0x01},"ARBITRARY_EXPLICIT_PRIME_CURVES"},
	{{0xFF,0x02},"ARBITRARY_EXPLICIT_CHAR2_CURVES"},
	{{0x00,0x00},NULL},
};

const struct id1 ecpointformat[]=
{
	{{0x00},"UNCOMPRESSED"},
	{{0x01},"ANSIX962-COMPRESSED-PRIME"},
	{{0x02},"ANSIX962-COMPRESSED-CHAR2"},
	{{0x00},NULL},
};

const struct id1 statusrequest[]=
{
	{{0x01},"OCSP"},
	{{0x02},"OCSP-MULTI"},
	{{0x00},NULL},
};

const struct id2 sigalg[]=
{
	{{0x02,0x01},"RSA-PKCS1-SHA1"},
	{{0x02,0x02},"SHA1-DSA"},
	{{0x02,0x03},"ECDSA-SHA1"},
	{{0x03,0x01},"SHA224-RSA"},
	{{0x03,0x02},"SHA224-DSA"},
	{{0x03,0x03},"SHA224-ECDSA"},
	{{0x04,0x01},"RSA-PKCS1-SHA256"},
	{{0x04,0x02},"SHA256-DSA"},
	{{0x04,0x03},"ECDSA-SECP256R1-SHA256"},
	{{0x04,0x20},"RSA-PKCS1-SHA256-LEGACY"},
	{{0x05,0x01},"RSA-PKCS1-SHA384"},
	{{0x05,0x02},"SHA384-DSA"},
	{{0x05,0x03},"ECDSA-SECP384R1-SHA384"},
	{{0x05,0x20},"RSA-PKCS1-SHA384-LEGACY"},
	{{0x06,0x01},"RSA-PKCS1-SHA512"},
	{{0x06,0x02},"SHA512-DSA"},
	{{0x06,0x03},"ECDSA-SECP521R1-SHA512"},
	{{0x06,0x20},"RSA-PKCS1-SHA512-LEGACY"},
	{{0x07,0x04},"ECCSI-SHA256"},
	{{0x07,0x05},"ISO-IBS1"},
	{{0x07,0x06},"ISO-IBS2"},
	{{0x07,0x07},"ISO-CHINESE-IBS"},
	{{0x07,0x08},"SM2SIG-SM3"},
	{{0x07,0x09},"GOSTR34102012-256A"},
	{{0x07,0x0A},"GOSTR34102012-256B"},
	{{0x07,0x0B},"GOSTR34102012-256C"},
	{{0x07,0x0C},"GOSTR34102012-256D"},
	{{0x07,0x0D},"GOSTR34102012-512A"},
	{{0x07,0x0E},"GOSTR34102012-512B"},
	{{0x07,0x0F},"GOSTR34102012-512C"},
	{{0x08,0x04},"RSA-PSS-RSAE-SHA256"},
	{{0x08,0x05},"RSA-PSS-RSAE-SHA384"},
	{{0x08,0x06},"RSA-PSS-RSAE-SHA512"},
	{{0x08,0x07},"ED25519"},
	{{0x08,0x08},"ED448"},
	{{0x08,0x09},"RSA-PSS-PSS-SHA256"},
	{{0x08,0x0A},"RSA-PSS-PSS-SHA384"},
	{{0x08,0x0B},"RSA-PSS-PSS-SHA512"},
	{{0x08,0x1A},"ECDSA-BRAINPOOLP256R1TLS13-SHA256"},
	{{0x08,0x1B},"ECDSA-BRAINPOOLP384R1TLS13-SHA384"},
	{{0x08,0x1C},"ECDSA-BRAINPOOLP512R1TLS13-SHA512"},
	{{0x00,0x00},NULL},
};

const struct id1 pskkeyexchange[]=
{
	{{0x00},"PSK-KE"},
	{{0x01},"PSK-DHE-KE"},
	{{0x00},NULL},
};

const struct id2 compcert[]=
{
	{{0x00,0x02},"BROTLI"},
	{{0x00,0x00},NULL},
};
