/*
 * bnls.h
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#ifndef BNLS_H_
#define BNLS_H_

#include "sys_types.h"

#ifndef PACKED
#ifdef __GNUC__
#define PACKED __attribute__((__packed__))
#else
#define PACKED
#endif
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#define ZERO_SIZE_ARRAY_SIZE	0
#else
#define ZERO_SIZE_ARRAY_SIZE	1
#endif

struct bnls_hdr {
	u_int16_t	len PACKED;
	u_int8_t	id PACKED;
	u_int8_t	data[ZERO_SIZE_ARRAY_SIZE] PACKED;
};
#define SIZEOF_BNLS_HDR		(3)

#define BNLS_NULL					((u_int8_t) 0x00)
#define BNLS_CDKEY					((u_int8_t) 0x01)
#define BNLS_LOGONCHALLENGE			((u_int8_t) 0x02)
#define BNLS_LOGONPROOF				((u_int8_t) 0x03)
#define BNLS_CREATEACCOUNT			((u_int8_t) 0x04)
#define BNLS_CHANGECHALLENGE		((u_int8_t) 0x05)
#define BNLS_CHANGEPROOF			((u_int8_t) 0x06)
#define BNLS_UPGRADECHALLENGE		((u_int8_t) 0x07)
#define BNLS_UPGRADEPROOF			((u_int8_t) 0x08)
#define BNLS_VERSIONCHECK			((u_int8_t) 0x09)
#define BNLS_CONFIRMLOGON			((u_int8_t) 0x0A)
#define BNLS_HASHDATA				((u_int8_t) 0x0B)
#define BNLS_CDKEY_EX				((u_int8_t) 0x0C)
#define BNLS_CHOOSENLSREVISION		((u_int8_t) 0x0D)
#define BNLS_AUTHORIZE				((u_int8_t) 0x0E)
#define BNLS_AUTHORIZEPROOF			((u_int8_t) 0x0F)
#define BNLS_REQUESTVERSIONBYTE		((u_int8_t) 0x10)
#define BNLS_VERIFYSERVER			((u_int8_t) 0x11)
#define BNLS_RESERVESERVERSLOTS		((u_int8_t) 0x12)
#define BNLS_SERVERLOGONCHALLENGE	((u_int8_t) 0x13)
#define BNLS_SERVERLOGONPROOF		((u_int8_t) 0x14)
#define BNLS_VERSIONCHECKEX			((u_int8_t) 0x18)
#define BNLS_VERSIONCHECKEX2		((u_int8_t) 0x1A)
#define BNLS_WARDEN					((u_int8_t) 0x7D)

#endif /* BNLS_H_ */
