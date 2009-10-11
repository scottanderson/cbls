/*
 * bnls.h
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#ifndef BNLS_H_
#define BNLS_H_

#include "cbls_packet.h"

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
	uint16_t len PACKED;
	uint8_t  id PACKED;
	uint8_t  data[ZERO_SIZE_ARRAY_SIZE] PACKED;
};
#define SIZEOF_BNLS_HDR		(3)

#define PRODUCT_STAR (0x01)
#define PRODUCT_SEXP (0x02)
#define PRODUCT_W2BN (0x03)
#define PRODUCT_D2DV (0x04)
#define PRODUCT_D2XP (0x05)
#define PRODUCT_JSTR (0x06)
#define PRODUCT_WAR3 (0x07)
#define PRODUCT_W3XP (0x08)
#define PRODUCT_DRTL (0x09)
#define PRODUCT_DSHR (0x0A)
#define PRODUCT_SSHR (0x0B)

#define PRODUCT_FIRST PRODUCT_STAR
#define PRODUCT_LAST PRODUCT_SSHR

#define BNLS_NULL					((uint8_t) 0x00)
#define BNLS_CDKEY					((uint8_t) 0x01)
#define BNLS_LOGONCHALLENGE			((uint8_t) 0x02)
#define BNLS_LOGONPROOF				((uint8_t) 0x03)
#define BNLS_CREATEACCOUNT			((uint8_t) 0x04)
#define BNLS_CHANGECHALLENGE		((uint8_t) 0x05)
#define BNLS_CHANGEPROOF			((uint8_t) 0x06)
#define BNLS_UPGRADECHALLENGE		((uint8_t) 0x07)
#define BNLS_UPGRADEPROOF			((uint8_t) 0x08)
#define BNLS_VERSIONCHECK			((uint8_t) 0x09)
#define BNLS_CONFIRMLOGON			((uint8_t) 0x0A)
#define BNLS_HASHDATA				((uint8_t) 0x0B)
#define BNLS_CDKEY_EX				((uint8_t) 0x0C)
#define BNLS_CHOOSENLSREVISION		((uint8_t) 0x0D)
#define BNLS_AUTHORIZE				((uint8_t) 0x0E)
#define BNLS_AUTHORIZEPROOF			((uint8_t) 0x0F)
#define BNLS_REQUESTVERSIONBYTE		((uint8_t) 0x10)
#define BNLS_VERIFYSERVER			((uint8_t) 0x11)
#define BNLS_RESERVESERVERSLOTS		((uint8_t) 0x12)
#define BNLS_SERVERLOGONCHALLENGE	((uint8_t) 0x13)
#define BNLS_SERVERLOGONPROOF		((uint8_t) 0x14)
#define BNLS_VERSIONCHECKEX			((uint8_t) 0x18)
#define BNLS_VERSIONCHECKEX2		((uint8_t) 0x1A)
#define BNLS_WARDEN					((uint8_t) 0x7D)

typedef void (*bnls_packet_handler_t)(struct packet_reader *);
void bnls_null(struct packet_reader *pr);
void bnls_cdkey(struct packet_reader *pr);
void bnls_logonchallenge(struct packet_reader *pr);
void bnls_logonproof(struct packet_reader *pr);
void bnls_createaccount(struct packet_reader *pr);
void bnls_changechallenge(struct packet_reader *pr);
void bnls_changeproof(struct packet_reader *pr);
void bnls_upgradechallenge(struct packet_reader *pr);
void bnls_upgradeproof(struct packet_reader *pr);
void bnls_versioncheck(struct packet_reader *pr);
void bnls_confirmlogon(struct packet_reader *pr);
void bnls_hashdata(struct packet_reader *pr);
void bnls_cdkey_ex(struct packet_reader *pr);
void bnls_choosenlsrevision(struct packet_reader *pr);
void bnls_authorize(struct packet_reader *pr);
void bnls_authorizeproof(struct packet_reader *pr);
void bnls_requestversionbyte(struct packet_reader *pr);
void bnls_verifyserver(struct packet_reader *pr);
void bnls_reserveserverslots(struct packet_reader *pr);
void bnls_serverlogonchallenge(struct packet_reader *pr);
void bnls_serverlogonproof(struct packet_reader *pr);
void bnls_versioncheckex(struct packet_reader *pr);
void bnls_versioncheckex2(struct packet_reader *pr);
void bnls_warden(struct packet_reader *pr);

#endif /* BNLS_H_ */
