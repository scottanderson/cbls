/*
 * protocol.c
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#include <string.h>
#include "protocol.h"
#include "cbls_server.h"
#include "bnls.h"
#include "http.h"
#include "debug.h"

extern void cbls_log (const char *fmt, ...);

// cbls->read_in has new data off the wire; copy data to cbls->in
uint32_t
decode (struct qbuf *qdst, struct qbuf *qsrc)
{
    uint32_t len, max, inused, inlen;

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
cbls_protocol_decide(struct cbls_conn *cbls) {
    if(cbls->in.pos < 3)
        return;
    if(!memcmp(cbls->in.buf, "GET", 3))
        cbls->rcv = http_protocol_rcv;
    else
        cbls->rcv = bnls_protocol_rcv;
    cbls->rcv(cbls);
}

void
bnls_protocol_rcv(struct cbls_conn *cbls)
{
    while(cbls->in.pos >= SIZEOF_BNLS_HDR) {
        struct packet_reader pr;
        bnls_packet_handler_t handler;

        read_init(&pr, cbls);

        if(!read_valid(&pr)) {
            cbls_close(cbls);
            return;
        }

        if(!read_ready(&pr))
            break;

        /* recieved a complete packet; bump the user idle timer */
        gettimeofday(&cbls->idle_tv, 0);

        /* big switch for packet ids */
        switch(pr.ih->id) {
        case BNLS_NULL:
            handler = bnls_null;
            break;

        case BNLS_CDKEY:
            handler = bnls_cdkey;
            break;

        case BNLS_LOGONCHALLENGE:
            handler = bnls_logonchallenge;
            break;

        case BNLS_LOGONPROOF:
            handler = bnls_logonproof;
            break;

        case BNLS_CREATEACCOUNT:
            handler = bnls_createaccount;
            break;

        case BNLS_CHANGECHALLENGE:
            handler = bnls_changechallenge;
            break;

        case BNLS_CHANGEPROOF:
            handler = bnls_changeproof;
            break;

        case BNLS_UPGRADECHALLENGE:
            handler = bnls_upgradechallenge;
            break;

        case BNLS_UPGRADEPROOF:
            handler = bnls_upgradeproof;
            break;

        case BNLS_VERSIONCHECK:
            handler = bnls_versioncheck;
            break;

        case BNLS_CONFIRMLOGON:
            handler = bnls_confirmlogon;
            break;

        case BNLS_HASHDATA:
            handler = bnls_hashdata;
            break;

        case BNLS_CDKEY_EX:
            handler = bnls_cdkey_ex;
            break;

        case BNLS_CHOOSENLSREVISION:
            handler = bnls_choosenlsrevision;
            break;

        case BNLS_AUTHORIZE:
            handler = bnls_authorize;
            break;

        case BNLS_AUTHORIZEPROOF:
            handler = bnls_authorizeproof;
            break;

        case BNLS_REQUESTVERSIONBYTE:
            handler = bnls_requestversionbyte;
            break;

        case BNLS_VERIFYSERVER:
            handler = bnls_verifyserver;
            break;

        case BNLS_RESERVESERVERSLOTS:
            handler = bnls_reserveserverslots;
            break;

        case BNLS_SERVERLOGONCHALLENGE:
            handler = bnls_serverlogonchallenge;
            break;

        case BNLS_SERVERLOGONPROOF:
            handler = bnls_serverlogonproof;
            break;

        case BNLS_VERSIONCHECKEX:
            handler = bnls_versioncheckex;
            break;

        case BNLS_VERSIONCHECKEX2:
            handler = bnls_versioncheckex2;
            break;

        case BNLS_WARDEN:
            handler = bnls_warden;
            break;

        default:
            handler = 0;
            break;
        }

        if(handler) {
            handler(&pr);
            /* handler could have called cbls_close */
            if (!cbls_files[cbls->fd].conn.cbls)
                return;
        } else {
            // Received unknown packet
            packet_log("RECV unknown packet", pr.ih);
            cbls_close(cbls);
            return;
        }

        // Remove the packet from the buffer
        read_end(&pr);
    }
}

#include "cbls_fd.h"

void
http_protocol_rcv(struct cbls_conn *cbls) {
    int i;
    if(i = decode(&cbls->out, &cbls->in)) {
        cbls_log("[%u] decoded %u bytes", cbls->uid, i);
        cbls_fd_set(cbls->fd, FDW);
    }
}
