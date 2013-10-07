// SHA2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "sha2.h"

#include <iostream>
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
int preProcess(unsigned char* ppMessage, unsigned char* message, int len)
{
	//+1 byte for the appended 1 at the end of the message.
	int paddingSize = (((len + 1) % 64) > 56) ? (56 + (64 - ((len) % 64))) : 56 - ((len) % 64); // TODO: Clean this up and optimize
	int ppMessageLength = len + paddingSize + 8;
	
	// Append 1 as the first bit, then fill the padding with 0s
	ppMessage = (unsigned char *)calloc(ppMessageLength, 1);
	//ppMessage = (unsigned char *)malloc(ppMessageLength);
	
	memcpy(ppMessage, message, len);
	ppMessage[len] = 0x80;
	//memset((ppMessage + len + 1), 0, (paddingSize - 1) + 8);

	// At the end of the padding, add the length (big endian) of the original message.
	memcpy((ppMessage + len + paddingSize), &len, sizeof(len));
	return ppMessageLength;
} 

void scheduler(unsigned char* messageChunk, unsigned int *schedulerArray)
{
	// The scheduler array.
	//unsigned int w[64];				// The scheduler uses a 64 words (32bit/word) schedule array
	schedulerArray = (unsigned int*)malloc(256);
	memcpy(schedulerArray, messageChunk, 64);

	unsigned int s0, s1;			// Scheduler temporary variables
	for (int i = 16; i < 64; ++i)
	{
		s0 = (_rotr(schedulerArray[i-15], 7) ^ _rotr(schedulerArray[i-15], 18) ^ (schedulerArray[i-15] >> 3));
		s1 = (_rotr(schedulerArray[i-2], 17) ^ _rotr(schedulerArray[i-2],  19) ^ (schedulerArray[i-2] >> 10));
		schedulerArray[i] = schedulerArray[i-16] + s0 + schedulerArray[i-7] + s1;
	}
}

void compressor(unsigned int* schedulerArray, s_hashValues &hValues)
{
	// Compression algorithm temporary variables.
	unsigned int a = hValues.h0;
	unsigned int b = hValues.h1;
	unsigned int c = hValues.h2;
	unsigned int d = hValues.h3;
	unsigned int e = hValues.h4;
	unsigned int f = hValues.h5;
	unsigned int g = hValues.h6;
	unsigned int h = hValues.h7;
	
	// Declare temporary work variables
	unsigned int S1, ch, temp1, S0, maj, temp2;
	for (int i = 0; i < 64; ++i)
	{
		// Main compression function algorithm.
		S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
		ch = (e & f) ^ ((!e) & g);
		temp1 = h + S1 + ch + k[i] + schedulerArray[i];
		S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
		maj = (a & b) ^ (a & c) ^ (b &c);
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

//void hashChunk(


void SHA256(unsigned char finalHash[256], unsigned char* message, int len)
{
	// Initialize the hash values
	s_hashValues hash;
	hash.h0 = 0x6a09e667;
	hash.h1 = 0xbb67ae85;
	hash.h2 = 0x3c6ef372;
	hash.h3 = 0xa54ff53a;
	hash.h4 = 0x510e527f;
	hash.h5 = 0x9b05688c;
	hash.h6 = 0x1f83d9ab;
	hash.h7 = 0x5be0cd19;

	// Preprocess the message
	unsigned char *ppMessage = NULL;
	int ppMessageLength = preProcess(ppMessage, message, len);
	int nbChunks = ppMessageLength >> 6 ;	// Devide by 64bytes (512bits).

	// Initialize the scheduler array
	unsigned int* schedulerArray = (unsigned int*) malloc(256);

	// For each message chunk, go through the scheduler and compressor
	for (int i = 0; i < nbChunks; ++i)
	{
		scheduler(&ppMessage[i << 6], schedulerArray);
		compressor(schedulerArray, hash);
	}

	// Cleanup
	free(schedulerArray);
	free(ppMessage);

	// return appended hash
	memcpy(&finalHash[0], &hash, 256);
}

int _tmain(int argc, _TCHAR* argv[])
{


	// Test functions
	/*
	cout << "10: " << preProcess(nullptr, 10);
	cout << "\n512: " << preProcess(nullptr, 512);
	cout << "\n510: " << preProcess(nullptr, 510);
	cout << "\n0: " << preProcess(nullptr, 0);
	cout << "\n56: " << preProcess(nullptr, 56);
	cout << "\n55: " << preProcess(nullptr, 55);
	*/
	unsigned char test[10] = {'a','b','c','d','e','f','g','h','i','j'};
	unsigned char* ppMessage = NULL;

	int msgLen = preProcess(ppMessage, test, 10);

	return 0;
}

