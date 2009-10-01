/*
 * cbls_packet_handler.c
 *
 *  Created on: Oct 1, 2009
 *      Author: sanderson
 */

#include <string.h>
#include <stdlib.h>
#include "sys_types.h"
#include "sys_net.h"
#include "cbls.h"
#include "cbls_packet.h"
#include "bnls.h"
#include "debug.h"
#include "bncsutil.h"

extern void cbls_log (const char *fmt, ...);

void
bnls_null(struct packet_reader *pr) {
	// keep-alive
}

void
bnls_cdkey(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (DWORD)  Server Token
	 * (STRING) CD-Key, no dashes or spaces
	 */
	u_int32_t server_token;
	char *cdkey;

	if(!read_dword(pr, &server_token)
	|| !(cdkey = read_string(pr))) {
		cbls_close(cbls);
		return;
	}

	/***/
	u_int32_t result;
	u_int32_t client_token = (u_int32_t)rand();
	u_int32_t hash[9];

	result = !kd_quick(cdkey, client_token, server_token,
			&hash[2], &hash[1], (void*)&hash[4], 20);

	if(result) {
		// Success
		hash[0] = strlen(cdkey);
		hash[3] = 0;
	} else {
		// Failure
		memset(hash, 0, 36);
	}

	/**
	 * (BOOLEAN)  Result
	 * (DWORD)    Client Token
	 * (DWORD[9]) CD key data for SID_AUTH_CHECK
	 */
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_CDKEY, 4);
	write_dword(&pw, result);
	write_dword(&pw, client_token);
	write_raw(&pw, hash, 36);
	write_end(&pw);
}

void
bnls_logonchallenge(struct packet_reader *pr) {
	/**
	 * (STRING) Account Name
	 * (STRING) Password
	 */

	/**
	 * (DWORD[8]) Data for SID_AUTH_ACCOUNTLOGON
	 */
}

void
bnls_logonproof(struct packet_reader *pr) {
	/**
	 * (DWORD[16]) Data from SID_AUTH_ACCOUNTLOGON
	 */

	/**
	 * (DWORD[5]) Data for SID_AUTH_ACCOUNTLOGONPROOF
	 */
}

void
bnls_createaccount(struct packet_reader *pr) {
	/**
	 * (STRING) Account Name
	 * (STRING) Password
	 */

	/**
	 * (DWORD[16]) Data for SID_AUTH_ACCOUNTCREATE
	 */
}

void
bnls_changechallenge(struct packet_reader *pr) {
	/**
	 * (STRING) Account Name
	 * (STRING) Account's Old Password
	 * (STRING) Account's New Password
	 */

	/**
	 * (DWORD[8]) Data for SID_AUTH_ACCOUNTCHANGE
	 */
}

void
bnls_changeproof(struct packet_reader *pr) {
	/**
	 * (DWORD[16]) Data from SID_AUTH_ACCOUNTCHANGE
	 */

	/**
	 * (DWORD[21]) Data for SID_AUTH_ACCOUNTCHANGEPROOF
	 */
}

void
bnls_upgradechallenge(struct packet_reader *pr) {
	/**
	 * (STRING) Account Name
	 * (STRING) Account's Old Password
	 * (STRING) Account's New Password (May be identical to old password, but still must be provided.)
	 */

	/**
	 * (BOOLEAN) Success code
	 */
}

void
bnls_upgradeproof(struct packet_reader *pr) {
	/**
	 * (DWORD)    Client Token
	 * (DWORD[5]) Old Password Hash
	 * (DWORD[8]) New Password Salt
	 * (DWORD[8]) New Password Verifier
	 */

	/**
	 * (DWORD[22]) Data for SID_AUTH_ACCOUNTUPGRADEPROOF
	 */
}

void
bnls_versioncheck(struct packet_reader *pr) {
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
}

void
bnls_confirmlogon(struct packet_reader *pr) {
	/**
	 * (DWORD[5]) Password proof from Battle.net
	 */

	/**
	 * (BOOLEAN) Success
	 */
}

void
bnls_hashdata(struct packet_reader *pr) {
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
}

void
bnls_cdkey_ex(struct packet_reader *pr) {
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
}

void
bnls_choosenlsrevision(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (DWORD) NLS Revision Number
	 */
	u_int32_t nls_rev;
	if(!read_dword(pr, &nls_rev)) {
		cbls_close(cbls);
		return;
	}

	/**
	 * (BOOLEAN) Success code
	 */
	struct packet_writer pw;
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
}

void
bnls_authorize(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (STRING) Bot ID
	 */
	char *botid;
	if(!(botid = read_string(pr))) {
		cbls_close(cbls);
		return;
	}

	/***/
	cbls_log("[%u] logging in as %s", cbls->uid, botid);

	/**
	 * (BOOLEAN) Server code
	 */
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_AUTHORIZE, 4);
	write_dword(&pw, 0);
	write_end(&pw);
}

void
bnls_authorizeproof(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (DWORD) Checksum
	 */

	/***/
	cbls_log("[%u] login success", cbls->uid);

	/**
	 * (DWORD) Status code (0=Authorized, 1=Unauthorized)
	 */
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_AUTHORIZEPROOF, 4);
	write_dword(&pw, 0);
	write_end(&pw);
}

void
bnls_requestversionbyte(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (DWORD) Product ID
	 */
	u_int32_t prod;
	if(!read_dword(pr, &prod)) {
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
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_REQUESTVERSIONBYTE, 8);
	write_dword(&pw, prod);
	if(prod != 0)
		write_dword(&pw, verb);
	write_end(&pw);
}

void
bnls_verifyserver(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (DWORD)     Server's IP
	 * (DWORD[32]) Signature
	 */

	/***/
	u_int32_t success = 0;

	/**
	 * (BOOLEAN) Success
	 */
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_VERIFYSERVER, 4);
	write_dword(&pw, success);
	write_end(&pw);
}

void
bnls_reserveserverslots(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (DWORD) Number of slots to reserve
	 * BNLS may limit the number of slots to a reasonable value
	 */

	/***/
	u_int32_t slots = 0;

	/**
	 * (DWORD) Number of slots reserved
	 */
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_RESERVESERVERSLOTS, 4);
	write_dword(&pw, slots);
	write_end(&pw);
}

void
bnls_serverlogonchallenge(struct packet_reader *pr) {
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
}

void
bnls_serverlogonproof(struct packet_reader *pr) {
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
}

void
bnls_versioncheckex(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
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

	if (!read_dword(pr, &productid)
	|| !read_dword(pr, &version_dll)
	|| !read_dword(pr, &flags)
	|| !read_dword(pr, &cookie)
	|| !(checksum_formula = read_string(pr))) {
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
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_VERSIONCHECKEX2, 8);
	write_dword(&pw, 0);
	write_dword(&pw, cookie);
	write_end(&pw);}

void
bnls_versioncheckex2(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
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

	if (!read_dword(pr, &productid)
	|| !read_dword(pr, &flags)
	|| !read_dword(pr, &cookie)
	|| !read_qword(pr, &timestamp)
	|| !(vc_filename = read_string(pr))
	|| !(checksum_formula = read_string(pr))) {
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
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_VERSIONCHECKEX2, 8);
	write_dword(&pw, 0);
	write_dword(&pw, cookie);
	write_end(&pw);
}

void
bnls_warden(struct packet_reader *pr) {
	struct cbls_conn *cbls = pr->cbls;
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
	if(!read_byte(pr, &usage)
	|| !read_dword(pr, &cookie)) {
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
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_WARDEN, 8);
	write_byte(&pw, usage);
	write_dword(&pw, cookie);
	write_byte(&pw, 0x04); // error executing warden module
	write_word(&pw, 0);
	write_end(&pw);
}
