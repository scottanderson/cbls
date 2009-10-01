/*
 * cbls_protocol.c
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#include <string.h>
#include <stdlib.h>
#include "sys_types.h"
#include "sys_net.h"
#include "cbls.h"
#include "bnls.h"
#include "cbls_packet.h"
#include "debug.h"
#include "bncsutil\bncsutil.h"

extern void cbls_log (const char *fmt, ...);

// cbls->read_in has new data off the wire; copy data to cbls->in
u_int32_t
decode (struct qbuf *qdst, struct qbuf *qsrc)
{
	u_int32_t len, max, inused, inlen;

	inlen = qsrc->len;
	if (!inlen)
		return 0;
	inused = 0;
	len = inlen;
	qsrc->pos = 0;

	max = qdst->len;
	if (max && inlen > max) {
		inused = max;
		len = max;
	} else {
		inused = inlen;
		len = inlen;
	}

	if (qdst->len < len)
		qbuf_set(qdst, qdst->pos, len);
	memcpy(&qdst->buf[qdst->pos], &qsrc->buf[qsrc->pos], len);
	if (inlen != inused) {
		/* Move unread source data to the front */
		memmove(&qsrc->buf[0], &qsrc->buf[inused], inlen - inused);
	}
	qsrc->pos = inlen - inused;
	qsrc->len -= inused;
	qdst->pos += len;
	if (len > qdst->len) {
		/* More data than expected */
		qdst->len = 0;
	} else
		qdst->len -= len;

	return (qdst->len == 0) ? 1 : 0;
}

void
cbls_protocol_rcv(struct cbls_conn *cbls)
{
	struct packet_reader pr;
	struct packet_writer pw;

	while(cbls->in.pos >= SIZEOF_BNLS_HDR) {
		read_init(&pr, cbls);

		if(!read_valid(&pr)) {
			cbls_close(cbls);
			return;
		}

		if(!read_ready(&pr))
			break;

		switch(pr.ih->id) {
		case BNLS_NULL:
			// keep-alive
			break;
			
		case BNLS_CDKEY: {
			/**
			 * (DWORD)  Server Token
			 * (STRING) CD-Key, no dashes or spaces
			 */
			u_int32_t server_token;
			char *cdkey;

			if(!read_dword(&pr, &server_token)
			|| !(cdkey = read_string(&pr))) {
				cbls_close(cbls);
				return;
			}

			/***/
			u_int32_t result = 0;
			u_int32_t client_token = (u_int32_t)rand();
			u_int32_t hash[9];

			int i;
			for(i = 0; i < 9; i++)
				hash[i] = 0;

			/**
			 * (BOOLEAN)  Result
			 * (DWORD)    Client Token
			 * (DWORD[9]) CD key data for SID_AUTH_CHECK
			 */
			write_init(&pw, cbls, BNLS_CDKEY, 4);
			write_dword(&pw, result); // fail
			write_dword(&pw, client_token);
			for(i = 0; i < 9; i++)
				write_dword(&pw, hash[i]);
			write_end(&pw);
			break;
		}

		case BNLS_LOGONCHALLENGE: {
			/**
			 * (STRING) Account Name
			 * (STRING) Password
			 */

			/**
			 * (DWORD[8]) Data for SID_AUTH_ACCOUNTLOGON
			 */
			break;
		}

		case BNLS_LOGONPROOF: {
			/**
			 * (DWORD[16]) Data from SID_AUTH_ACCOUNTLOGON
			 */

			/**
			 * (DWORD[5]) Data for SID_AUTH_ACCOUNTLOGONPROOF
			 */
			break;
		}

		case BNLS_CREATEACCOUNT: {
			/**
			 * (STRING) Account Name
			 * (STRING) Password
			 */

			/**
			 * (DWORD[16]) Data for SID_AUTH_ACCOUNTCREATE
			 */
			break;
		}

		case BNLS_CHANGECHALLENGE: {
			/**
			 * (STRING) Account Name
			 * (STRING) Account's Old Password
			 * (STRING) Account's New Password
			 */

			/**
			 * (DWORD[8]) Data for SID_AUTH_ACCOUNTCHANGE
			 */
			break;
		}

		case BNLS_CHANGEPROOF: {
			/**
			 * (DWORD[16]) Data from SID_AUTH_ACCOUNTCHANGE
			 */

			/**
			 * (DWORD[21]) Data for SID_AUTH_ACCOUNTCHANGEPROOF
			 */
			break;
		}

		case BNLS_UPGRADECHALLENGE: {
			/**
			 * (STRING) Account Name
			 * (STRING) Account's Old Password
			 * (STRING) Account's New Password (May be identical to old password, but still must be provided.)
			 */

			/**
			 * (BOOLEAN) Success code
			 */
			break;
		}

		case BNLS_UPGRADEPROOF: {
			/**
			 * (DWORD)    Client Token
			 * (DWORD[5]) Old Password Hash
			 * (DWORD[8]) New Password Salt
			 * (DWORD[8]) New Password Verifier
			 */

			/**
			 * (DWORD[22]) Data for SID_AUTH_ACCOUNTUPGRADEPROOF
			 */
			break;
		}

		case BNLS_VERSIONCHECK: {
			/**
			 * (DWORD)  Product ID
			 * (DWORD)  Version DLL digit in the range 0-7 (For example, for IX86Ver1.mpq, the digit is 1)
			 * (STRING) Checksum Formula
			 */

			/**
			 * (BOOLEAN) Success
			 *
			 * If Success is TRUE:
			 * (DWORD)   Version
			 * (DWORD)   Checksum
			 * (STRING)  Version check stat string
			 */
			break;
		}

		case BNLS_CONFIRMLOGON: {
			/**
			 * (DWORD[5]) Password proof from Battle.net
			 */

			/**
			 * (BOOLEAN) Success
			 */
			break;
		}

		case BNLS_HASHDATA: {
			/**
			 * (DWORD) 		The size of the data to be hashed. Note: This is no longer restricted to 64 bytes.
			 * (DWORD) 		Flags
			 * (VOID)		Data to be hashed.
			 *
			 * Optional Data:
			 * (DWORD)		Client key. Present only if HASHDATA_FLAG_DOUBLEHASH (0x02) is specified.
			 * (DWORD)		Server key. Present only if HASHDATA_FLAG_DOUBLEHASH (0x02) is specified.
			 * (DWORD)		Cookie. Present only if HASHDATA_FLAG_COOKIE (0x04) is specified.
			 */

			/**
			 * (DWORD[5]) The data hash.
			 *
			 * Optional:
			 * (DWORD) Cookie. Same as the cookie from the request.
			 */
			break;
		}

		case BNLS_CDKEY_EX: {
			/**
			 * (DWORD)    Cookie. This value has no special meaning to the server and will simply be echoed to the client in the response.
			 * (BYTE)     Amount of CD-keys to encrypt. Must be between 1 and 32.
			 * (DWORD)    Flags
			 * (DWORD[])  Server session key(s) (optional; check flags)
			 * (DWORD[])  Client session key(s) (optional; check flags)
			 * (STRING[]) CD-keys. No dashes or spaces. The client can use multiple types of CD-keys in the same packet.
			 */

			/**
			 * (DWORD) Cookie
			 * (BYTE)  Number of CD-keys requested
			 * (BYTE)  Number of successfully ecrypted CD-keys
			 * (DWORD) Bit mask
			 *
			 * For each successful CD Key:
			 * (DWORD)    Client session key
			 * (DWORD[9]) CD-key data.
			 */
			break;
		}

		case BNLS_CHOOSENLSREVISION: {
			/**
			 * (DWORD) NLS Revision Number
			 */
			u_int32_t nls_rev;
			if(!read_dword(&pr, &nls_rev)) {
				cbls_close(cbls);
				return;
			}

			/**
			 * (BOOLEAN) Success code
			 */
			write_init(&pw, cbls, BNLS_CHOOSENLSREVISION, 4);
			if (nls_rev < 0 || nls_rev > 2) {
				//Unsuccessful, unknown NLS Type
				write_dword(&pw, 0);
			} else {
				//Successful
				write_dword(&pw, 1);
				cbls->nls_rev = nls_rev;
			}
			write_end(&pw);
			break;
		}

		case BNLS_AUTHORIZE: {
			/**
			 * (STRING) Bot ID
			 */
			char *botid;
			if(!(botid = read_string(&pr))) {
				cbls_close(cbls);
				return;
			}

			/***/
			cbls_log("[%u] logging in as %s", cbls->uid, botid);

			/**
			 * (BOOLEAN) Server code
			 */
			write_init(&pw, cbls, BNLS_AUTHORIZE, 4);
			write_dword(&pw, 0);
			write_end(&pw);
			break;
		}

		case BNLS_AUTHORIZEPROOF: {
			/**
			 * (DWORD) Checksum
			 */

			/***/
			cbls_log("[%u] login success", cbls->uid);

			/**
			 * (DWORD) Status code (0=Authorized, 1=Unauthorized)
			 */
			write_init(&pw, cbls, BNLS_AUTHORIZEPROOF, 4);
			write_dword(&pw, 0);
			write_end(&pw);
			break;
		}

		case BNLS_REQUESTVERSIONBYTE: {
			/**
			 * (DWORD) Product ID
			 */
			u_int32_t prod;
			if(!read_dword(&pr, &prod)) {
				prod = 0;
			}

			/***/
			// FIXME: don't hard-code version bytes
			u_int32_t verb;
			switch(prod) {
			case 1: case 2:  verb = 0xd3; break;
			case 3:          verb = 0x4f; break;
			case 4: case 5:  verb = 0x0c; break;
			case 6:          verb = 0xa9; break;
			case 7: case 8:  verb = 0x17; break;
			case 9: case 10: verb = 0x2a; break;
			case 11:         verb = 0x1a; break;
			default:
				prod = 0;
			}

			/**
			 * (DWORD) Product ID (0 for error)
			 *
			 * If product is non-zero:
			 * (DWORD) Version byte
			 */
			write_init(&pw, cbls, BNLS_REQUESTVERSIONBYTE, 8);
			write_dword(&pw, prod);
			if(prod != 0)
				write_dword(&pw, verb);
			write_end(&pw);
			break;
		}

		case BNLS_VERIFYSERVER: {
			/**
			 * (DWORD)     Server's IP
			 * (DWORD[32]) Signature
			 */

			/***/
			u_int32_t success = 0;

			/**
			 * (BOOLEAN) Success
			 */
			write_init(&pw, cbls, BNLS_VERIFYSERVER, 4);
			write_dword(&pw, success);
			write_end(&pw);
			break;
		}

		case BNLS_RESERVESERVERSLOTS: {
			/**
			 * (DWORD) Number of slots to reserve
			 * BNLS may limit the number of slots to a reasonable value
			 */

			/***/
			u_int32_t slots = 0;

			/**
			 * (DWORD) Number of slots reserved
			 */
			write_init(&pw, cbls, BNLS_RESERVESERVERSLOTS, 4);
			write_dword(&pw, slots);
			write_end(&pw);
			break;
		}

		case BNLS_SERVERLOGONCHALLENGE: {
			/**
			 * (DWORD)     Slot Index
			 * (DWORD)     NLS Revision Number
			 * (DWORD[16]) Data from Account Database
			 * (DWORD[8])  Data from SID_AUTH_ACCOUNTLOGON
			 */

			/**
			 * (DWORD)     Slot index
			 * (DWORD[16]) Data for SID_AUTH_ACCOUNTLOGON
			 */
			break;
		}

		case BNLS_SERVERLOGONPROOF:
			/**
			 * (DWORD)    Slot Index
			 * (DWORD[5]) Data from SID_AUTH_ACCOUNTLOGONPROOF
			 * (STRING)   The client's Account Name
			 */

			/**
			 * (DWORD)    Slot index.
			 * (BOOLEAN)  Success
			 * (DWORD[5]) Data for SID_AUTH_ACCOUNTLOGONPROOF
			 */
			break;

		case BNLS_VERSIONCHECKEX: {
			/**
			 * (DWORD)  Product ID
			 * (DWORD)  Version DLL digit in the range 0-7 (For example, for IX86Ver1.mpq, the digit is 1)
			 * (DWORD)  Flags (must be set to 0 or you will be disconnected!)
			 * (DWORD)  Cookie
			 * (STRING) Checksum Formula
			 */
			u_int32_t productid;
			u_int32_t version_dll;
			u_int32_t flags;
			u_int32_t cookie;
			char *checksum_formula;

			if (!read_dword(&pr, &productid)
			|| !read_dword(&pr, &version_dll)
			|| !read_dword(&pr, &flags)
			|| !read_dword(&pr, &cookie)
			|| !(checksum_formula = read_string(&pr))) {
				cbls_close(cbls);
				return;
			}

			/***/

			/**
			 * (BOOLEAN) Success
			 *
			 * If success is true:
			 * (DWORD)  Version
			 * (DWORD)  Checksum
			 * (STRING) Version check stat string
			 * (DWORD)  Cookie
			 * (DWORD)  The latest version code for this product
			 *
			 * Otherwise:
			 * (DWORD) Cookie
			 */
			write_init(&pw, cbls, BNLS_VERSIONCHECKEX2, 8);
			write_dword(&pw, 0);
			write_dword(&pw, cookie);
			write_end(&pw);
			break;
		}

		case BNLS_VERSIONCHECKEX2: {
			/**
			 * (DWORD)  Product ID
			 * (DWORD)  Flags (must be set to 0 or you will be disconnected!)
			 * (DWORD)  Cookie
			 * (QWORD)  Timestamp for Version Check Archive
			 * (STRING) Version Check Archive Filename
			 * (STRING) Checksum Formula
			 */
			u_int32_t productid;
			u_int32_t flags;
			u_int32_t cookie;
			u_int64_t timestamp;
			char *vc_filename;
			char *checksum_formula;

			if (!read_dword(&pr, &productid)
			|| !read_dword(&pr, &flags)
			|| !read_dword(&pr, &cookie)
			|| !read_qword(&pr, &timestamp)
			|| !(vc_filename = read_string(&pr))
			|| !(checksum_formula = read_string(&pr))) {
				cbls_close(cbls);
				return;
			}

			/***/

			/**
			 * (BOOLEAN) Success
			 *
			 * If success is true:
			 * (DWORD)  Version
			 * (DWORD)  Checksum
			 * (STRING) Version check stat string
			 * (DWORD)  Cookie
			 * (DWORD)  The latest version code for this product
			 *
			 * Otherwise:
			 * (DWORD) Cookie
			 */
			write_init(&pw, cbls, BNLS_VERSIONCHECKEX2, 8);
			write_dword(&pw, 0);
			write_dword(&pw, cookie);
			write_end(&pw);
			break;
		}

		case BNLS_WARDEN: {
			/**
			 * (BYTE)  Usage
			 * (DWORD) Cookie
			 *
			 * Usage 0x00
			 * (DWORD)  Client
			 * (WORD)   Length of Seed (should be 4 always)
			 * (VOID)   Seed
			 * (STRING) Username
			 * (WORD)   Length of password
			 * (VOID)   Password
			 *
			 * Usage 0x01
			 * (WORD) Length of Warden Packet
			 * (VOID) Warden Packet Data
			 */
			u_int8_t usage;
			u_int32_t cookie;
			if(!read_byte(&pr, &usage)
			|| !read_dword(&pr, &cookie)) {
				cbls_close(cbls);
				return;
			}

			/***/

			/**
			 * (BYTE)  Usage
			 * (DWORD) Cookie
			 * (BYTE)  Result
			 * (WORD)  Lengh of data
			 * (VOID)  Data
			 */
			write_init(&pw, cbls, BNLS_WARDEN, 8);
			write_byte(&pw, usage);
			write_dword(&pw, cookie);
			write_byte(&pw, 0x04); // error executing warden module
			write_word(&pw, 0);
			write_end(&pw);
			break;
		}

		default:
			// Received unknown packet
			packet_log("RECV unknown packet", pr.ih);
			cbls_close(cbls);
			return;
		}

		// Remove the packet from the buffer
		read_end(&pr);
	}
}
