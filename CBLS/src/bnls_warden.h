/*
 * bnls_warden.h
 *
 *  Created on: Oct 8, 2009
 *      Author: sanderson
 */

#ifndef BNLS_WARDEN_H_
#define BNLS_WARDEN_H_

#define WARDEN_RESULT_SUCCESS 0x00
/**
 * Command 0x00: The server has reached its designated limit
 * Command 0x01: The cookie was not initialized with command 0x00, or it has timed out/was removed
 */
#define WARDEN_RESULT_UNKNOWN_PACKET_HANDLER 0x01
/**
 * Command 0x01: Incoming warden data was unreadable after decryption
 */
#define WARDEN_RESULT_INCOMING_DATA_CORRUPT 0x02
/**
 * Battle.net has switched to another module and the server doesn't have it yet; try again later
 */
#define WARDEN_RESULT_WARDEN_MODULE_NOT_LOADED 0x03
/**
 * BNLS was unable to load and/or execute the given warden module
 */
#define WARDEN_RESULT_ERROR_EXECUTING_WARDEN_MODULE 0x04
/**
 * Your client is not supported
 */
#define WARDEN_RESULT_UNSUPPORTED_CLIENT 0x05
/**
 * BNLS was unable to read the warden 0x02 packet
 */
#define WARDEN_RESULT_WARDEN_HACK_CHECK_ERROR 0x06
/**
 *
 - The offsets have probly changed and the BNLS server is not yet aware.
 */
#define WARDEN_RESULT_WARDEN_CHECK_INVALID 0x07
/**
 *
 - This is used with useage 0x02.
 - Currently, only warden packet 0x05 is supported.
 */
#define WARDEN_RESULT_INCOMING_WARDEN_PACKET_UNSUPPORTED 0x08
/**
 *
 - This is used with useage 0x03.
 - BNLS is not yet able to process this info type.
 - Currentl supported info types are: 0x01
 */
#define WARDEN_RESULT_UNSUPPORTED_WARDEN_INFO_TYPE 0x09
/**
 *
 - This is used with useage 0x00.
 - Currently, that method is open for all to use. (leave user name and password as blank strings)
 - In the future, if the sevrer is being abused, it maybe required of you, to use a BNLS username and password.
 */
#define WARDEN_RESULT_INVALID_PASSOWRD 0xFD
#define WARDEN_RESULT_INVALID_USERNAME 0xFE
/**
 *
 - You're BNLS 0x7D packet had bad format, or sizes.
 - The "data" in the responce, may contain an offset into you're packet, where the problem is.
 */
#define WARDEN_RESULT_REQUEST_CORRUPT 0xFF

void snd_warden(struct cbls_conn *cbls, u_int8_t command, u_int32_t cookie, u_int16_t data_len, void *data);
void snd_warden_error(struct cbls_conn *cbls, u_int8_t command, u_int32_t cookie, u_int8_t result);
void bnls_warden_0(struct packet_reader *pr, u_int32_t cookie);
void bnls_warden_1(struct packet_reader *pr, u_int32_t cookie);
void bnls_warden_2(struct packet_reader *pr, u_int32_t cookie);
void bnls_warden_3(struct packet_reader *pr, u_int32_t cookie);

#endif /* BNLS_WARDEN_H_ */
