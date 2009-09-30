/*
 * cbls_protocol.c
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#include <string.h>
#include "sys_types.h"
#include "sys_net.h"
#include "cbls.h"
#include "bnls.h"
#include "cbls_fd.h"
#include "debug.h"

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

struct packet_writer {
	struct cbls_conn *cbls;
	struct bnls_hdr *oh;
	int qbuf_offset;
};

/**
 * Initialize a packet writer. The length is just a hint; you may go over.
 */
void
write_init(struct packet_writer *pw, struct cbls_conn *cbls, int packetid, int min_length) {
	struct bnls_hdr *oh;
	struct qbuf *out;

	out = &cbls->out;

	pw->qbuf_offset = out->len;
	qbuf_set(out, out->pos, pw->qbuf_offset + SIZEOF_BNLS_HDR + min_length);
	oh = (struct bnls_hdr *)&out->buf[out->pos + pw->qbuf_offset];
	oh->id = packetid;
	oh->len = SIZEOF_BNLS_HDR;

	pw->cbls = cbls;
	pw->oh = oh;
}

void
write_raw(struct packet_writer *pw, void *data, int len) {
	struct qbuf *out = &pw->cbls->out;
    struct bnls_hdr *oh = pw->oh;

    int write_pos = oh->len - SIZEOF_BNLS_HDR;
    oh->len += len;
    if(out->len < pw->qbuf_offset + oh->len)
        qbuf_set(out, out->pos, pw->qbuf_offset + oh->len);
    memcpy(&oh->data[write_pos], data, len);
}

void
write_dword(struct packet_writer *pw, u_int32_t value) {
	write_raw(pw, &value, 4);
}

void
write_end(struct packet_writer *pw) {
	cbls_fd_set(pw->cbls->fd, FDW);

	/*packet_log("SEND", pw->oh);*/
}

void
cbls_protocol_rcv(struct cbls_conn *cbls)
{
	struct qbuf *in;
	struct bnls_hdr *hdr;
	struct packet_writer pw;

	in = &cbls->in;

	/*cbls_log("cbls_protocol_recv[%d] qbuf size is %d", cbls->fd, in->pos);*/

	while(in->pos >= SIZEOF_BNLS_HDR) {
		hdr = (struct bnls_hdr *)&in->buf[0];

		if(hdr->id > BNLS_VERSIONCHECKEX2) {
			cbls_log("Invalid packet id 0x%X", hdr->id);
			cbls_close(cbls);
			return;
		}

		if(hdr->len > 0xFF) {
			cbls_log("Invalid packet len 0x%X", hdr->len);
			cbls_close(cbls);
			return;
		}

		if(in->pos < hdr->len) {
			/*cbls_log("Packet incomplete [%d/%d]", in->pos, hdr->len);*/
			break;
		}

		switch(hdr->id) {
		case BNLS_NULL:
			/* No response from the server from this message. Simply a keep-alive.
			 */
			break;
			
		case BNLS_CDKEY:
			/* (DWORD) 		Session key from Battle.net. This is the second DWORD in SID_AUTH_INFO (0x50)
			 * (STRING)		CD-Key. No dashes or spaces.
			 */

		case BNLS_LOGONCHALLENGE:
			/* (STRING) 	Account Name
			 * (STRING) 	Password
			 */

		case BNLS_LOGONPROOF:
			/* (16 DWORDs) 	Data for SID_AUTH_ACCOUNTLOGON (0x53)
			 */

		case BNLS_CREATEACCOUNT:
			/* (STRING) 	Account Name
			 * (STRING) 	Password
			 */

		case BNLS_CHANGECHALLENGE:
			/* (STRING) 	Account Name
			 * (STRING) 	Account's Old Password
			 * (STRING) 	Account's New Password
			 */

		case BNLS_CHANGEPROOF:
			/* (16 DWORDs) Data from SID_AUTH_ACCOUNTCHANGE (0x55)
			 */

		case BNLS_UPGRADECHALLENGE:
			/* (STRING) 	Account Name
			 * (STRING) 	Account's Old Password
			 * (STRING) 	Account's New Password (May be identical to old password, but still must be provided.)
			 */

		case BNLS_UPGRADEPROOF:
			/* (22 DWORDs) 	Data for SID_AUTH_ACCOUNTUPGRADEPROOF (0x58)
			 */

		case BNLS_VERSIONCHECK:
			/* (DWORD) 		Product ID
			 * (DWORD) 		Version DLL digit in the range 0-7 (For example, for IX86Ver1.mpq, the digit is 1)
			 * (STRING) 	Checksum Formula
			 */

		case BNLS_CONFIRMLOGON:
			/* (5 DWORDs) Password proof from Battle.net
			 */

		case BNLS_HASHDATA:
			/* (DWORD) 		The size of the data to be hashed. Note: This is no longer restricted to 64 bytes.
			 * (DWORD) 		Flags
			 * (VARIANT)	Data to be hashed.
			 * Optional Data:
			 * (DWORD)		Client key. Present only if HASHDATA_FLAG_DOUBLEHASH (0x02) is specified.
			 * (DWORD)		Server key. Present only if HASHDATA_FLAG_DOUBLEHASH (0x02) is specified.
			 * (DWORD)		Cookie. Present only if HASHDATA_FLAG_COOKIE (0x04) is specified.
			 */

		case BNLS_CDKEY_EX:
			/* (DWORD) 				Cookie. This value has no special meaning to the server and will simply be echoed to the client in the response.
			 * (BYTE)				Amount of CD-keys to encrypt. Must be between 1 and 32.
			 * (DWORD)				Flags
			 * (DWORD(s))			Server session key(s), depending on the flags.
			 * (OPTIONAL DWORD(s)) 	Client session key(s), depending on the flags.
			 * (STRING(s))			CD-keys. No dashes or spaces. The client can use multiple types of CD-keys in the same packet.
			 */

		case BNLS_CHOOSENLSREVISION:
			/* (DWORD)		NLS Revision Number
			 */

		case BNLS_AUTHORIZE:
			/* (STRING) Bot ID
			 */
			write_init(&pw, cbls, BNLS_AUTHORIZE, 4);
			write_dword(&pw, 0); // (DWORD) Server code
			write_end(&pw);
			break;

		case BNLS_AUTHORIZEPROOF:
			/* (DWORD) Checksum
			 */
			write_init(&pw, cbls, BNLS_AUTHORIZEPROOF, 4);
			write_dword(&pw, 0); // (DWORD) 0=Authorized, 1=Unauthorized
			write_end(&pw);
			break;

		case BNLS_REQUESTVERSIONBYTE: {
			/* (DWORD) Product ID
			 */
			u_int32_t prod = *(u_int32_t*)&hdr->data[0];
			u_int32_t verb;
			if(hdr->len < 4)
				prod = 0;
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
				verb = 0;
			}

			write_init(&pw, cbls, BNLS_REQUESTVERSIONBYTE, 8);
			write_dword(&pw, prod); // (DWORD) Product ID (0 for error)
			write_dword(&pw, verb); // (DWORD) Version byte
			write_end(&pw);
			break; }

		case BNLS_VERIFYSERVER:
			/* (DWORD) 		Server's IP
			 * (128 bytes) 	Signature
			 */

		case BNLS_RESERVESERVERSLOTS:
			/* (DWORD) 		Number of slots to reserve
			 * BNLS may limit the number of slots to a reasonable value.
			 */

		case BNLS_SERVERLOGONCHALLENGE:
			/* (DWORD) 		Slot Index
			 * (DWORD)		NLS Revision Number
			 * (16 DWORDs)	Data from Account Database
			 * (8 DWORDs)	Data from the client's SID_AUTH_ACCOUNTLOGON (0x53) request
			 */

		case BNLS_SERVERLOGONPROOF:
			/* (DWORD) 		Slot Index
			 * (5 DWORDs)	Data from the clien't SID_AUTH_ACCOUNTLOGONPROOF (0x54) request
			 * (STRING)		The client's Account Name
			 */

		case BNLS_VERSIONCHECKEX:
			/* (DWORD)		Product ID
			 * (DWORD)		Version DLL digit in the range 0-7 (For example, for IX86Ver1.mpq, the digit is 1)
			 * (DWORD)		Flags (must be set to 0 or you will be disconnected!)
			 * (DWORD)		Cookie
			 * (STRING)		Checksum Formula
			 */

		case BNLS_VERSIONCHECKEX2:
			/* (DWORD)		Product ID
			 * (DWORD)		Flags (must be set to 0 or you will be disconnected!)
			 * (DWORD)		Cookie
			 * (ULONGLONG)	Timestamp for Version Check Archive
			 * (STRING)		Version Check Archive Filename
			 * (STRING)		Checksum Formula
			 */

		default:
			// Received unknown packet
			packet_log("RECV unknown packet", hdr);
			cbls_close(cbls);
			return;
		}

		// Remove the packet from the buffer
		if(in->pos != hdr->len)
			memmove(&in->buf[0], &in->buf[hdr->len], in->pos - hdr->len);
		in->pos -= hdr->len;
	}
}
