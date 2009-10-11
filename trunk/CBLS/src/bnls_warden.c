/*
 * bnls_warden.c
 *
 *  Created on: Oct 8, 2009
 *      Author: Scott
 */

#include "bnls.h"
#include "bnls_warden.h"

void __inline__
snd_warden(struct cbls_conn *cbls, uint8_t command, uint32_t cookie, uint16_t data_len, void *data) {
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
snd_warden_error(struct cbls_conn *cbls, uint8_t command, uint32_t cookie, uint8_t result) {
	struct packet_writer pw;
	write_init(&pw, cbls, BNLS_WARDEN, 8);
	write_byte(&pw, command);
	write_dword(&pw, cookie);
	write_byte(&pw, result);
	write_word(&pw, 0);
	write_end(&pw);
}

void
bnls_warden_0(struct packet_reader *pr, uint32_t cookie) {
	/**
	 * (DWORD)  Client
	 * (WORD)   Length of Seed (should be 4 always)
	 * (VOID)   Seed
	 * (STRING) Username
	 * (WORD)   Length of password
	 * (VOID)   Password
	 */
	uint32_t client;
	uint16_t seed_len;
	void *seed;
	char *username;
	uint16_t password_len;
	void *password;

	if(!read_dword(pr, &client)
	|| !read_word(pr, &seed_len)
	|| !(seed = read_void(pr, seed_len))
	|| !(username = read_string(pr))
	|| !read_word(pr, &password_len)
	|| !(password = read_void(pr, password_len))) {
		snd_warden_error(pr->cbls, 0, cookie, WARDEN_RESULT_REQUEST_CORRUPT);
		return;
	}

	/***/
	snd_warden_error(pr->cbls, 0, cookie, WARDEN_RESULT_UNKNOWN_PACKET_HANDLER);
}

void
bnls_warden_1(struct packet_reader *pr, uint32_t cookie) {
	/**
	 * (WORD) Lengh Of Warden Packet
	 * (VOID) Warden Packet Data
	 */
	uint16_t payload_len;
	void *payload;

	if(!read_word(pr, &payload_len)
	|| !(payload = read_void(pr, payload_len))) {
		snd_warden_error(pr->cbls, 1, cookie, WARDEN_RESULT_REQUEST_CORRUPT);
		return;
	}

	/***/
	snd_warden_error(pr->cbls, 1, cookie, WARDEN_RESULT_UNKNOWN_PACKET_HANDLER);
}

void
bnls_warden_2(struct packet_reader *pr, uint32_t cookie) {
	/**
	 * (DWORD)    Client
	 * (WORD)     Lengh Of Seed
	 * (VOID)     Seed
	 * (DWORD)    Unused
	 * (BYTE[16]) Module MD5 Name
	 * (WORD)     Lengh of Warden 0x05 packet
	 * (VOID)     Warden 0x05 packet
	 */
	uint32_t client;
	uint16_t seed_len;
	void *seed;
	uint32_t unused;
	void *mod_md5_name;
	uint16_t payload_len;
	void *payload;

	if(!read_dword(pr, &client)
	|| !read_word(pr, &seed_len)
	|| !(seed = read_void(pr, seed_len))
	|| !read_dword(pr, &unused)
	|| !(mod_md5_name = read_void(pr, 16))
	|| !read_word(pr, &payload_len)
	|| !(payload = read_void(pr, payload_len))) {
		snd_warden_error(pr->cbls, 2, cookie, WARDEN_RESULT_REQUEST_CORRUPT);
		return;
	}

	/***/
	snd_warden_error(pr->cbls, 2, cookie, WARDEN_RESULT_INCOMING_WARDEN_PACKET_UNSUPPORTED);
}

void
bnls_warden_3(struct packet_reader *pr, uint32_t cookie) {
	/**
	 * (DWORD)    Client
	 * (DWORD)    Info Type (0x01)
	 * (WORD)     Unused (must be 0x00)
	 * (VOID)     Unused
	 */
	uint32_t client;
	uint32_t info_type;
	uint16_t unused;

	if(!read_dword(pr, &client)
	|| !read_dword(pr, &info_type)
	|| !read_word(pr, &unused)
	|| (unused != 0)) {
		snd_warden_error(pr->cbls, 3, cookie, WARDEN_RESULT_REQUEST_CORRUPT);
		return;
	}

	/***/
	snd_warden_error(pr->cbls, 3, cookie, WARDEN_RESULT_UNSUPPORTED_WARDEN_INFO_TYPE);
}
