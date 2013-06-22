/**
 * File: base64.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines functions for performing Base64 encoding/decoding operations.
 *		- Defines some macros to help implement these operations.
 */

#ifndef BASE64_H
#define BASE64_H

#include <cctype>
#include <string>
#include <stdint.h>
#include <gmpxx.h>

#include "../Data_Conv/data_conv_prims.h"

#define CATR_BITS(a,b,n)	((((a) << (n)) & 0xFF) | (((b) >> (8 - (n))) & 0xFF))
#define CATL_BITS(a,b,n)	((((a) << (8 - (n))) & 0xFF) | (((b) >> (n)) & 0xFF))

static const std::string b64_chars =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 Encryption Macro
#define B64_ENC_BLOCK(a,b,i)												\
{																			\
	(a) += b64_chars[((b)[(i)] >> 2) & 0x3F];								\
	(a) += b64_chars[(CATL_BITS((b)[(i)], (b)[(i) + 1], 2) >> 2) & 0x3F];	\
	(a) += b64_chars[CATR_BITS((b)[(i) + 1], (b)[(i) + 2], 2) & 0x3F];		\
	(a) += b64_chars[(b)[(i) + 2] & 0x3F];									\
}

// Base64 Decryption Macro
#define B64_DEC_BLOCK(a,b,i)							\
{														\
	(a)[(i)] = CATR_BITS((b)[0], (b)[1] << 2, 2);		\
	(a)[(i) + 1] = CATR_BITS((b)[1], (b)[2] << 2, 4);	\
	(a)[(i) + 2] = CATL_BITS((b)[2], (b)[3] << 2, 2);	\
}

/**
 * Postcondition: ascii_str is base64 encoded and the result is
 *		copied to b64_str.
 */
void	base64_encode(std::string &b64_str, std::string ascii_str);

/**
 * Precondition: mpi should be a positive integer.
 * Postcondition: mpi is separated into its individual bytes, base64
 *		encoded, and copied to b64_str.
 */
void	base64_encode(std::string &b64_str, mpz_class mpi);

/**
 * Precondition: input must have at least len number of indices.
 * Postcondition: len bytes of input are base64 encoded, and the
 *		result is copied to b64_str.
 */
void	base64_encode(std::string &b64_str, uint8_t *input, size_t len);

/**
 * Precondition: b64_str is a base64 encoded string.
 * Postcondition: b64_str is decoded and the result is copied to
 *		ascii_str.
 */
int		base64_decode(std::string &ascii_str, std::string b64_str);

/**
 * Precondition: Same as above overloaded base64_decode function.
 * Postcondition: b64_str is decoded and the resulting bytes are
 *		concatenated into a multiple precision integer, mpi.
 */
int		base64_decode(mpz_class &mpi, std::string b64_str);

/**
 * Precondition: b64_str is a base64 encoded string, and *output
 *		should not be pointing at any allocated memory.
 * Postcondition: Memory is allocated for *output and the result
 *		of decoding b64_str is stored in that memory location. len
 *		is set to the number of indices in output.
 */
int		base64_decode(uint8_t **output, size_t &len, std::string b64_str);

/*** Helper Functions */

/**
 * Precondition: block should have at least (index + 5) characters.
 * Postcondition: The base64 character indices are stored in vals array.
 *		Returns false if any of the characters were not base64
 *		characters, and true otherwise.
 */
bool	b64_block_vals(uint8_t vals[4], std::string block, int index);

/**
 * Postcondition: Returns the bae64 character index of ch character. If
 *		ch is not a base64 character, then -1 is returned.
 */
int		b64_index(char ch);

#endif		/* BASE64_H */
