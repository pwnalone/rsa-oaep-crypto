/**
 * File: base64.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the functions defined in base64.h header file.
 */

#include "base64.h"

void base64_encode(std::string &b64_str, std::string ascii_str)
{
	size_t		length = ascii_str.length();
	uint8_t		*tmp_input = new uint8_t[length];

	// Copy string into a uint8_t array
	for (size_t i = 0; i < length; i++)
		tmp_input[i] = ascii_str[i];

	// Call overloaded encoding function on array
	base64_encode(b64_str, tmp_input, length);

	delete[] tmp_input;
	tmp_input = NULL;

	return;
}

void base64_encode(std::string &b64_str, mpz_class mpi)
{
	size_t		mpi_bytes = 0;
	mpz_class	mpi_copy (mpi);
	uint8_t		*tmp_input;

	// Calculates number of bytes in mpi
	while (mpi_copy > 0)
	{
		mpi_copy /= 256;
		mpi_bytes++;
	}

	// Copy bytes from mpi into a uint8_t array
	tmp_input = new uint8_t[mpi_bytes];
	I2OSP(tmp_input, mpi, mpi_bytes);

	// Call overloaded encoding function on array
	base64_encode(b64_str, tmp_input, mpi_bytes);

	delete[] tmp_input;
	tmp_input = NULL;

	return;
}

void base64_encode(std::string &b64_str, uint8_t *input, size_t len)
{
	if (!len) return;

	size_t			blocks = len / 3;
	int				extra_bytes = len % 3;
	uint8_t			tmp_block[3];
	std::string		tmp_enc;

	b64_str = "";
	tmp_enc = "";

	// Encode each full block (3 bytes)
	for (int i = 0; i < blocks; i++)
		B64_ENC_BLOCK(b64_str, input, i * 3)

	// Pad extra bytes and encode
	if (extra_bytes)
	{
		tmp_block[0] = input[blocks * 3];
		tmp_block[1] = (extra_bytes == 2) ? input[(blocks * 3) + 1] : 0x00;
		tmp_block[2] = 0x00;

		B64_ENC_BLOCK(tmp_enc, tmp_block, 0)

		// Equal signs used to denote padded bytes
		if (extra_bytes == 1)
		{
			b64_str.append(tmp_enc, 0, 2);
			b64_str += "==";
		}
		else
		{
			b64_str.append(tmp_enc, 0, 3);
			b64_str += "=";
		}
	}

	return;
}

int base64_decode(std::string &ascii_str, std::string b64_str)
{
	uint8_t		*tmp_output;
	size_t		tmp_len;

	// If decoding fails free memory and return with error code
	if (base64_decode(&tmp_output, tmp_len, b64_str) == 1)
	{
		delete[] tmp_output;
		tmp_output = NULL;

		return 1;
	}

	ascii_str = "";

	// Copy decoded bytes to ascii_str
	for (int i = 0; i < tmp_len; i++)
		ascii_str.push_back(tmp_output[i]);

	// Free memory
	delete[] tmp_output;
	tmp_output = NULL;

	return 0;
}

int base64_decode(mpz_class &mpi, std::string b64_str)
{
	uint8_t		*tmp_output;
	size_t		tmp_len;
	mpz_class	tmp_byte;

	// If decoding fails free memory and return with error code
	if (base64_decode(&tmp_output, tmp_len, b64_str) == 1)
	{
		delete[] tmp_output;
		tmp_output = NULL;

		return 1;
	}

	// Convert decoded value from uint8_t array to mpz_class variable
	OS2IP(mpi, tmp_output, tmp_len);

	// Free memory
	delete[] tmp_output;
	tmp_output = NULL;

	return 0;
}

int base64_decode(uint8_t **output, size_t &len, std::string b64_str)
{
	size_t		b64_len = b64_str.length();
	size_t		blocks = (b64_len / 4) - 1;

	int			extra_bytes;
	uint8_t		tmp_block[4];

	len = (b64_len / 4) * 3;	/* Base length (no extra bytes) */

	// Calculate length of decoded value
	if (b64_str[b64_len - 2] == '=') len -= 2;
	else if (b64_str[b64_len - 1] == '=') len--;
	else blocks++;

	// Allocate memory to store decoded value in
	extra_bytes = len % 3;
	*output = new uint8_t[len];

	/* Decode each full block and return with error code
	   if non-base64 characters are found in b64_str */
	for (int i = 0; i < blocks; i++)
	{
		if (!b64_block_vals(tmp_block, b64_str, i * 4))
			return 1;

		B64_DEC_BLOCK(*output, tmp_block, i * 3);
	}

	// Decode any extra bytes (non full blocks)
	if (extra_bytes)
	{
		b64_block_vals(tmp_block, b64_str, blocks * 4);

		// Return with error code for invalid characters
		if (tmp_block[0] == 0xFF || tmp_block[1] == 0xFF) return 1;
		if (extra_bytes == 2 && tmp_block[2] == 0xFF) return 1;

		(*output)[blocks * 3] = CATR_BITS(tmp_block[0],
				tmp_block[1] << 2, 2);

		// One more byte to decode if 2 extra bytes
		if (extra_bytes == 2)
		{
			(*output)[(blocks * 3) + 1] = CATR_BITS(tmp_block[1],
					tmp_block[2] << 2, 4);
		}
	}

	return 0;
}

/*** Helper Functions */

bool b64_block_vals(uint8_t vals[4], std::string block, int index)
{
	bool valid_block = true;

	// Get index of each base64 character in block
	for (int i = 0; i < 4; i++)
	{
		// If non-base64 character found
		if ((vals[i] = b64_index(block[index + i])) == 0xFF)
			valid_block = false;
	}

	return valid_block;
}

int	b64_index(char ch)
{
	if (isupper(ch))
		return (ch - 'A');

	else if (islower(ch))
		return 26 + (ch - 'a');

	else if (isdigit(ch))
		return 52 + (ch - '0');

	else if (ch == '+' || ch == '/')
		return (ch == '+') ? 62 : 63;

	return -1;		/* non-base64 character */
}
