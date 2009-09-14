/*
 * RC4Crypto.h
 *
 *  Created on: Sep 14, 2009
 *      Author: Jeffrey Shorf (jeffrey.shorf@gmail.com)
 */

#ifndef RC4CRYPTO_H_
#define RC4CRYPTO_H_

class RC4Crypto {
public:
	unsigned char* key;

	RC4Crypto(unsigned char* base);

};

#endif /* RC4CRYPTO_H_ */
