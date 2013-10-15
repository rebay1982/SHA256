// SHA2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "sha2.h"

#include <iostream>
#include <string.h>
using namespace std;

/*
 * Desc: This method prepares the message for hashing.
 *
 * PSEUDO CODE:
 * Pre-processing:
 * append the bit '1' to the message
 * append k bits '0', where k is the minimum number >= 0 such that the resulting message
 *   length (modulo 512 in bits) is 448.
 * append length of message (before pre-processing), in bits, as 64-bit big-endian integer
 * 
 */
uint preProcess(uchar* &ppMessage, uchar* message, uint len)
{
	//+1 byte for the appended 1 at the end of the message.s
	uint paddingSize = (((len + 1) % 64) > 56) ? (56 + (64 - ((len) % 64))) : 56 - ((len) % 64); // TODO: Clean this up and optimize
	uint ppMessageLength = len + paddingSize;
	
	// Append 1 as the first bit, then fill the padding with 0s (+ padding for bitlength over 64bits)
	ppMessage = (uchar*)calloc(ppMessageLength + 8, 1);
	memcpy(ppMessage, message, len);
	ppMessage[len] = 0x80;

	// Make the bit length fit on two unsigned longs (64bit);
	uint msgBitLen[2] = {0, 0};
	if ((len * 8) > 0xFFFFFFF) ++msgBitLen[1]; msgBitLen[0] += (len * 8);

	// At the end of the padding, add the bit length (big endian) of the original message.
	for (int i = 0; i < 4; ++i)
	{
		(ppMessage + ppMessageLength)[i]	 = (msgBitLen[1] >> ((3 - i) << 3)) & 0xFF;
		(ppMessage + ppMessageLength)[i + 4] = (msgBitLen[0] >> ((3 - i) << 3)) & 0xFF;
	}

	return (ppMessageLength + 8);
} 

void scheduler(uchar* messageChunk, uint* schedulerArray)
{
	// The scheduler array.
	// Copy over message chunk to first 16 words, switch endianness in the scheduler array (make big-endian)
	for (int i = 0; i < 16; ++i)
	{
		schedulerArray[i] = messageChunk[(i << 2)    ] << 24 |
							messageChunk[(i << 2) + 1] << 16 |
							messageChunk[(i << 2) + 2] <<  8 |
							messageChunk[(i << 2) + 3];
	}

	uint s0, s1;			// Scheduler temporary variables
	for (uint i = 16; i < 64; ++i)
	{
		s0 = (_rotr(schedulerArray[i-15], 7) ^ (_rotr(schedulerArray[i-15], 18)) ^ (schedulerArray[i-15] >> 3));
		s1 = (_rotr(schedulerArray[i-2], 17) ^ (_rotr(schedulerArray[i-2],  19)) ^ (schedulerArray[i-2] >> 10));
		schedulerArray[i] = schedulerArray[i-16] + s0 + schedulerArray[i-7] + s1;
	}
}

void compressor(uint* schedulerArray, s_hashValues &hValues)
{
	// Compression algorithm temporary variables.
	uint a = hValues.h0;
	uint b = hValues.h1;
	uint c = hValues.h2;
	uint d = hValues.h3;
	uint e = hValues.h4;
	uint f = hValues.h5;
	uint g = hValues.h6;
	uint h = hValues.h7;
	
	// Declare temporary work variables
	uint S1, ch, temp1, S0, maj, temp2;
	for (uint i = 0; i < 64; ++i)
	{
		// Main compression function algorithm.
		S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
		ch = (e & f) ^ ((~e) & g);
		temp1 = h + S1 + ch + k[i] + schedulerArray[i];
		S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		temp2 = S0 + maj;

		// Affect working variables.
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	// Update hashing values with current chunk compression.
	hValues.h0 += a;
	hValues.h1 += b;
	hValues.h2 += c;
	hValues.h3 += d;
	hValues.h4 += e;
	hValues.h5 += f;
	hValues.h6 += g;
	hValues.h7 += h;
}

/*
 * Desc: This method Hashes a message using the SHA256 method.
 *
 * Input:	unsigned char finalHash[32]:
 *				array to contain the final hash (string format)
 *			unsigned char* message:
 *				pointer to the message to hash (data or string)
 *			int len:
 *				Length of the message passed as input
 *
 * Output:	
 *
 */
void SHA256(uchar finalHash[32], uchar* message, uint len)
{
	// Initialize the hash values
	s_hashValues hash;

	// Big-endian constants
	hash.h0 = 0x6a09e667;
	hash.h1 = 0xbb67ae85;
	hash.h2 = 0x3c6ef372;
	hash.h3 = 0xa54ff53a;
	hash.h4 = 0x510e527f;
	hash.h5 = 0x9b05688c;
	hash.h6 = 0x1f83d9ab;
	hash.h7 = 0x5be0cd19;

	// Little-endian constants
	//hash.h0 = 0x67e6096a;
	//hash.h1 = 0x85ae67bb;
	//hash.h2 = 0x72f36e3c;
	//hash.h3 = 0x3af54fa5;
	//hash.h4 = 0x7f520e51;
	//hash.h5 = 0x8c68059b;
	//hash.h6 = 0xabd9831f;
	//hash.h7 = 0x19cde05b;

	// Preprocess the message
	uchar* ppMsg = NULL;
	uint ppMsgLen = preProcess(ppMsg, message, len);
	uint nbChunks = ppMsgLen >> 6 ;	// Devide by 64bytes (512bits).

	// Initialize the scheduler array
	uint* schedulerArray = (uint*) malloc(256);

	// For each message chunk, go through the scheduler and compressor
	for (uint i = 0; i < nbChunks; ++i)
	{
		scheduler(&ppMsg[i << 6], schedulerArray);
		compressor(schedulerArray, hash);
	}

	// Cleanup
	free(schedulerArray);
	free(ppMsg);

	// Return appended hash in big-endian
	for (int i = 0; i < 4; ++i)
	{
		finalHash[0  + i] = ((uchar*)&hash.h0)[3 - i];
		finalHash[4  + i] = ((uchar*)&hash.h1)[3 - i];
		finalHash[8  + i] = ((uchar*)&hash.h2)[3 - i];
		finalHash[12 + i] = ((uchar*)&hash.h3)[3 - i];
		finalHash[16 + i] = ((uchar*)&hash.h4)[3 - i];
		finalHash[20 + i] = ((uchar*)&hash.h5)[3 - i];
		finalHash[24 + i] = ((uchar*)&hash.h6)[3 - i];
		finalHash[28 + i] = ((uchar*)&hash.h7)[3 - i];
	}
}

void displayHash(uchar hash[32])
{
	printf("0x");
	
	for (int i = 0; i < 32; ++i)
	{
		printf("%x", hash[i]);
	}

	printf("\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	// Example on ""
	uchar test[] = "The quick brown fox jumps over the lazy dog";
	uchar finalHash[32];
	SHA256(finalHash, test, 43);

	displayHash(finalHash);

	// 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	return 0;
}