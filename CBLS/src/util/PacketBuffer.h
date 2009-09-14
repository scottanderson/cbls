/*
 * PacketBuffer.h
 *
 *  Created on: Sep 13, 2009
 *      Author: Jeffrey Shorf (jeffrey.shorf@gmail.com)
 */

#ifndef PACKETBUFFER_H_
#define PACKETBUFFER_H_

class DataInBuffer
{
public:
	DataInBuffer();
	~DataInBuffer();
protected:
	unsigned char in_data[];

	DataInBuffer::DataInBuffer()
	{

	}

	DataInBuffer::~DataInBuffer()
	{

	}
};

class DataOutBuffer
{
public:
	DataOutBuffer();
	~DataOutBuffer();
protected:
	unsigned char out_data[];

	DataOutBuffer::DataOutBuffer()
	{

	}

	DataOutBuffer::~DataOutBuffer()
	{

	}
};
#endif /* PACKETBUFFER_H_ */
