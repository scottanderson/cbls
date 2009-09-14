/*
 * PacketBuffer.h
 *
 *  Created on: Sep 13, 2009
 *      Author: Jeffrey Shorf (jeffrey.shorf@gmail.com)
 */

#ifndef PACKETBUFFER_H_
#define PACKETBUFFER_H_

#include <string.h>

class DataInBuffer
{
public:
	unsigned char* in_data;
	int in_len;

	DataInBuffer(unsigned char* buffer);
	~DataInBuffer();

};

DataInBuffer::DataInBuffer(unsigned char* buffer)
{
	if (strlen(buffer) != 0)
		in_data = buffer;
	in_len = 0;
}

DataInBuffer::~DataInBuffer()
{
	memset(in_data,'\0', in_len);
	in_len = 0;
}


class DataOutBuffer
{
private:
	unsigned char* out_data;
public:
	DataOutBuffer();
	~DataOutBuffer();
};

DataOutBuffer::DataOutBuffer()
{
	out_data = new unsigned char[32];
}

DataOutBuffer::~DataOutBuffer()
{

}
#endif /* PACKETBUFFER_H_ */
