/**
 * File: sha256.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the member functions of the SHA256_Hash class, defined in
 *			sha256.h header file.
 */

/* Note that for this file (sha256.cc) and the corresponding header
   file (sha256.h), a lot of the code is similar and a couple parts
   were even taken from the file that can be found at this link:
   http://www.spale.com/download/scrypt/scrypt1.0/sha256.c */

#include "sha256.h"

SHA256_Hash::SHA256_Hash(void)
{
	reset();
}

void SHA256_Hash::update(uint8_t *input, size_t length)
{
	if (!length) return;

	int	left, fill;

	// Update messge message length count (in bytes)
	m_total_fill_amt += length;

	// Calculate space left in data buffer
	left = 64 - m_buf_fill_amt;
	fill = (length <= left) ? length : left;

	// Copy as much of input as possible into data buffer
	memcpy(m_data_buf + m_buf_fill_amt, input, fill);

	// If data buffer is full, process data
	if (length >= left)
	{
		process();
		m_buf_fill_amt = 0;
	}
	else m_buf_fill_amt += length;
	
	length -= fill;
	input += fill;

	/* Process 512-bit (64 bytes) blocks of data at a time from
	   input, as long as input still has that much data available */
	while (length >= 64)
	{
		process(input);
		length -= 64;
		input += 64;
	}

	// Copy any remaining data from input to data buffer
	if (length > 0)
	{
		memcpy(m_data_buf, input, length);
		m_buf_fill_amt = length;
	}

	return;
}

void SHA256_Hash::update(std::string input)
{
	size_t	length = input.length();
	uint8_t	*inp_trans = new uint8_t[length];

	/* Convert data from std::string type input to
	   uint8_t type and transfer data into inp_trans */
	for (int i = 0; i < length; i++)
		inp_trans[i] = static_cast <uint8_t> (input[i]);

	update(inp_trans, length);

	delete[] inp_trans;
	inp_trans = NULL;

	return;
}

void SHA256_Hash::process(uint8_t *input)
{
	WORD msg_sched[64];
	WORD tmp1, tmp2;
	WORD a, b, c, d, e, f, g, h;	/* Working variables */

	// Calculate the message schedule
	for (int t = 0; t < 16; t++)
		UINT8_TO_32(msg_sched[t], input, t * 4)

	for (int t = 16; t < 64; t++)
	{
		msg_sched[t] = DOW1_256(msg_sched[t - 2]) + msg_sched[t - 7] +
					   DOW0_256(msg_sched[t - 15]) + msg_sched[t - 16];
	}

	// Set working variables to current hash value
	a = m_h[0];
	b = m_h[1];
	c = m_h[2];
	d = m_h[3];
	e = m_h[4];
	f = m_h[5];
	g = m_h[6];
	h = m_h[7];

	/* Perform hashing process on working variables
	   for each index of the message schedule */
	for (int t = 0; t < 64; t++)
	{
		tmp1 = h + SUM1_256(e) + CH(e, f, g) +
			   kwords[t] + msg_sched[t];

		tmp2 = SUM0_256(a) + MAJ(a, b, c);

		h = g;
		g = f;
		f = e;

		e = d + tmp1;

		d = c;
		c = b;
		b = a;

		a = tmp1 + tmp2;
	}

	/* Update hash value with the working variables by adding them
	   modulo 2^32 (Since m_h is an array of 32-bit WORDs, addition
	   modulo 2^32 happens automatically through integer overflow */
	m_h[0] += a;
	m_h[1] += b;
	m_h[2] += c;
	m_h[3] += d;
	m_h[4] += e;
	m_h[5] += f;
	m_h[6] += g;
	m_h[7] += h;

	return;
}

void SHA256_Hash::process(void)
{
	return process(m_data_buf);
}

void SHA256_Hash::finish(void)
{
	// Calculate space left in data buffer
	int	left = 64 - m_buf_fill_amt;

	/* If there isn't room enough for padding and the message
	   length, then fill the rest of the buffer with padding,
	   process it, and then fill the first 56 bytes of the buffer
	   with zeros (padding) */
	if ((left - 1) < 8)
	{
		memcpy(m_data_buf + m_buf_fill_amt, padding, left);
		process();
		memset(m_data_buf, 0x0, 56);
	}

	// Otherwise just fill all but 8 bytes with padding
	else
	{
		memcpy(m_data_buf + m_buf_fill_amt, padding, left - 8);
	}

	m_total_fill_amt *= BYTE_SIZE;	/* bytes to bits */

	/* Convert message length (m_total_fill_amt) to uint8_t
	   type and store it in last 8 bytes of data buffer */
	UINT32_TO_8(m_data_buf, m_total_fill_amt >> WORD_SIZE, 56);
	UINT32_TO_8(m_data_buf, m_total_fill_amt, 60);

	// Process final message block
	process();
	m_hash_done = true;

	return;
}

void SHA256_Hash::get_hash_val(WORD hval[8]) const
{
	if (!m_hash_done) return;

	// Copy hash value into hval
	for (int i = 0; i < 8; i++)
		hval[i] = m_h[i];

	return;
}

void SHA256_Hash::get_hash_val(uint8_t hval[32]) const
{
	if (!m_hash_done) return;

	/* Convert 32-bit WORDs of hash value
	   into octets and store them in hval */
	for (int i = 0; i < 8; i++)
		UINT32_TO_8(hval, m_h[i], i * 4)

	return;
}

void SHA256_Hash::get_hash_val(mpz_class &hval) const
{
	if (!m_hash_done) return;

	std::stringstream ss;

	// Fill ss stream with hash value (in hex)
	for (int i = 0; i < 8; i++)
		ss << std::hex << m_h[i];

	// Set hval to the string of ss (in hex)
	hval.set_str(ss.str(), 16);

	return;
}

void SHA256_Hash::reset(void)
{
	// Set hash to its initial WORD (32-bit) values
	m_h[0] = 0x6a09e667;
   	m_h[1] = 0xbb67ae85;
	m_h[2] = 0x3c6ef372;
	m_h[3] = 0xa54ff53a;
	m_h[4] = 0x510e527f;
	m_h[5] = 0x9b05688c;
	m_h[6] = 0x1f83d9ab;
	m_h[7] = 0x5be0cd19;

	// Set indices of data buffer to 0
	for (int i = 0; i < 64; i++)
		m_data_buf[i] = 0;

	// Set default values for other variables as well
	m_buf_fill_amt = 0;
	m_total_fill_amt = 0;

	m_hash_done = false;

	return;
}
