/*
 * bnls_warden.c
 *
 *  Created on: Oct 8, 2009
 *      Author: Scott
 */

#include "bnls.h"
#include "bnls_warden.h"

void __inline__
snd_warden(struct cbls_conn *cbls, u_int8_t command, u_int32_t cookie, u_int16_t data_len, void *data) {
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_WARDEN, 8 + data_len);
	write_byte(&pw, command);
	write_dword(&pw, cookie);
	write_byte(&pw, WARDEN_RESULT_SUCCESS);
	write_word(&pw, data_len);
	write_raw(&pw, data, data_len);
	write_end(&pw);
}

void __inline__
snd_warden_error(struct cbls_conn *cbls, u_int8_t command, u_int32_t cookie, u_int8_t result) {
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_WARDEN, 8);
	write_byte(&pw, command);
	write_dword(&pw, cookie);
	write_byte(&pw, result);
	write_word(&pw, 0);
	write_end(&pw);
}

void
bnls_warden_0(struct packet_reader *pr, u_int32_t cookie) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (DWORD)  Client
	 * (WORD)   Length of Seed (should be 4 always)
	 * (VOID)   Seed
	 * (STRING) Username
	 * (WORD)   Length of password
	 * (VOID)   Password
	 */
	u_int32_t client;
	u_int16_t seed_len;
	void *seed;
	char *username;
	u_int16_t password_len;
	void *password;

	if(!read_dword(pr, &client)
	|| !read_word(pr, &seed_len)
	|| !(seed = read_void(pr, seed_len))
	|| !(username = read_string(pr))
	|| !read_word(pr, &password_len)
	|| !(password = read_void(pr, password_len))) {
		cbls_close(cbls);
		return;
	}

	/***/
	snd_warden_error(pr->cbls, 0, cookie, WARDEN_RESULT_UNKNOWN_PACKET_HANDLER);
}

void
bnls_warden_1(struct packet_reader *pr, u_int32_t cookie) {
	struct cbls_conn *cbls = pr->cbls;
	/**
	 * (WORD) Lengh Of Warden Packet
	 * (VOID) Warden Packet Data
	 */
	u_int16_t payload_len;
	void *payload;

	if(!read_word(pr, &payload_len)
	|| !(payload = read_void(pr, payload_len))) {
		cbls_close(cbls);
		return;
	}

	/***/
	snd_warden_error(pr->cbls, 1, cookie, WARDEN_RESULT_UNKNOWN_PACKET_HANDLER);
}

void
bnls_warden_2(struct packet_reader *pr, u_int32_t cookie) {
	/**
	 * (DWORD)    Client
	 * (WORD)     Lengh Of Seed
	 * (VOID)     Seed
	 * (DWORD)    Unused
	 * (BYTE[16]) Module MD5 Name
	 * (WORD)     Lengh of Warden 0x05 packet
	 * (VOID)     Warden 0x05 packet
	 */

	/***/
	snd_warden_error(pr->cbls, 1, cookie, WARDEN_RESULT_INCOMING_WARDEN_PACKET_UNSUPPORTED);
}

void
bnls_warden_3(struct packet_reader *pr, u_int32_t cookie) {
	/**
	 * (DWORD)    Client
	 * (DWORD)    Info Type (0x01)
	 * (WORD)     Unused (must be 0x00)
	 * (VOID)     Unused
	 */

	/***/
	snd_warden_error(pr->cbls, 1, cookie, WARDEN_RESULT_UNSUPPORTED_WARDEN_INFO_TYPE);
}
