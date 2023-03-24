/*
 * bnls_packet.c
 *
 *  Created on: Sep 30, 2009
 *      Author: Scott
 */

#include <string.h>
#include "bnls.h"
#include "cbls_fd.h"
#include "debug.h" /* for packet_log() */

extern void cbls_log (const char *fmt, ...);

void
read_init(struct packet_reader *pr, struct cbls_conn *cbls) {
    pr->cbls = cbls;
    pr->ih = (void *)&cbls->in.buf[0];
    pr->pos = 0;
}

int
read_valid(struct packet_reader *pr) {
    struct bnls_hdr *hdr = pr->ih;

    if(hdr->len > 0xFF) {
        cbls_log("[%u] Invalid packet len 0x%X", pr->cbls->uid, hdr->len);
        return 0;
    }

    // Packet is valid
    return 1;
}


int
read_ready(struct packet_reader *pr) {
    struct qbuf *in = &pr->cbls->in;
    struct bnls_hdr *hdr = pr->ih;

    if(in->pos < hdr->len) {
        /*cbls_log("Packet incomplete [%d/%d]", in->pos, hdr->len);*/
        return 0;
    }

    // Packet is completely received
    return 1;
}

int
read_raw(struct packet_reader *pr, void *dest, int len) {
    struct bnls_hdr *hdr = pr->ih;

    if(hdr->len < SIZEOF_BNLS_HDR + pr->pos + len) {
        cbls_log("[%u] read_raw() failed at pos %u", pr->cbls->uid, pr->pos + SIZEOF_BNLS_HDR);
        packet_log("read_raw() failed", hdr);
        return 0;
    }

    memcpy(dest, &hdr->data[pr->pos], len);
    pr->pos += len;
    return 1;
}

int
read_byte(struct packet_reader *pr, uint8_t *dest) {
    return read_raw(pr, dest, 1);
}

int
read_word(struct packet_reader *pr, uint16_t *dest) {
    return read_raw(pr, dest, 2);
}

int
read_dword(struct packet_reader *pr, uint32_t *dest) {
    return read_raw(pr, dest, 4);
}

int
read_qword(struct packet_reader *pr, uint64_t *dest) {
    return read_raw(pr, dest, 8);
}

void*
read_void(struct packet_reader *pr, int len) {
    struct bnls_hdr *hdr = pr->ih;

    if(hdr->len < SIZEOF_BNLS_HDR + pr->pos + len) {
        cbls_log("[%u] read_void() failed at pos %u", pr->cbls->uid, pr->pos + SIZEOF_BNLS_HDR);
        packet_log("read_void() failed", hdr);
        return 0;
    }

    void *ret = &hdr->data[pr->pos];
    pr->pos += len;
    return ret;
}

char*
read_string(struct packet_reader *pr) {
    struct bnls_hdr *hdr = pr->ih;
    int endpos;

    // Validate that the buffer holds a null-terminated string
    for(endpos = pr->pos; endpos < hdr->len - SIZEOF_BNLS_HDR; endpos++) {
        if(hdr->data[endpos] == 0) {
            // We found the null terminator
            char *ret = &hdr->data[pr->pos];
            // Move the buffer position to after the null
            pr->pos = endpos + 1;
            return ret;
        }
    }

    // Couldn't validate the data
    cbls_log("[%u] read_string() failed at pos %u", pr->cbls->uid, pr->pos + SIZEOF_BNLS_HDR);
    packet_log("read_string() failed", hdr);
    return 0;
}

void
read_end(struct packet_reader *pr) {
    struct qbuf *in = &pr->cbls->in;
    /* copy the length out of the packet, because we can't point to it after memmove */
    uint16_t packet_len = pr->ih->len;

    if(in->pos != packet_len)
        memmove(&in->buf[0], &in->buf[packet_len], in->pos - packet_len);
    in->pos -= packet_len;
}

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
write_byte(struct packet_writer *pw, uint8_t value) {
    write_raw(pw, &value, 1);
}

void
write_word(struct packet_writer *pw, uint16_t value) {
    write_raw(pw, &value, 2);
}

void
write_dword(struct packet_writer *pw, uint32_t value) {
    write_raw(pw, &value, 4);
}

void
write_qword(struct packet_writer *pw, uint64_t value) {
    write_raw(pw, &value, 8);
}

void
write_string(struct packet_writer *pw, char *value) {
    if(value) {
        write_raw(pw, value, strlen(value)+1);
    } else {
        write_byte(pw, 0);
    }
}

void
write_end(struct packet_writer *pw) {
    cbls_fd_set(pw->cbls->fd, FDW);

    /*packet_log("SEND", pw->oh);*/
}
