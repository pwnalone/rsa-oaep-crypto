/**
 * File: sha256.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines the SHA256_Hash class which contains functions for generating
 *			a hash value of 256 bits in length for any seed value within size
 *			constraints (2^61 bytes).
 */

/* Note that for this file (sha256.h) and the corresponding C++ file
   (sha256.cc), a lot of the code is similar and a couple parts were
   even taken from the file that can be found at this link:
   http://www.spale.com/download/scrypt/scrypt1.0/sha256.c */

#ifndef SHA256_H
#define SHA256_H

#include <sstream>
#include <string>
#include <gmpxx.h>
#include <stdint.h>

#define WORD_SIZE			32		/* bits  */
#define BYTE_SIZE			8		/* bits  */
#define SHA256_DIGEST_LEN	32		/* bytes */

#define ROTR(x,n)	(((x) >> (n)) | ((x) << (WORD_SIZE - (n))))
#define ROTL(x,n)	(((x) << (n)) | ((x) >> (WORD_SIZE - (n))))
#define SHR(x,n)	((x) >> (n))

// Macros for some operations of the SHA-256 hashing algorithm
#define CH(x,y,z)	(((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SUM0_256(x)	(ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define SUM1_256(x)	(ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define DOW0_256(x)	(ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define DOW1_256(x)	(ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

// Macros for converting between uint8_t and uint32_t
#define UINT8_TO_32(b,a,i)					\
{											\
	(b) = ((uint32_t)(a)[(i)] << 24)		\
		  | ((uint32_t)(a)[(i) + 1] << 16)	\
		  | ((uint32_t)(a)[(i) + 2] << 8)	\
		  | ((uint32_t)(a)[(i) + 3]);		\
}

#define UINT32_TO_8(b,a,i)					\
{											\
	(b)[(i)] = ((a) >> 24) & 0xFF;			\
	(b)[(i) + 1] = ((a) >> 16) & 0xFF;		\
	(b)[(i) + 2] = ((a) >> 8) & 0xFF;		\
	(b)[(i) + 3] = (a) & 0xFF;				\
}

typedef uint32_t	WORD;

// SHA-256 constants (these can be calculated at runtime)
const WORD		kwords[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Maximum ammount of padding needed for a message
const uint8_t	padding[64] = {
	0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

/************************* class SHA256_Hash *************************
 *
 * SHA256_Hash(void);
 *		Postcondition: Calls the reset function (See reset function).
 *
 * void update(uint8_t *input, size_t length);
 *		Precondition: input has at least as much memory as length
 *			number of uint8_t values.
 *		Postcondition: Hash value is updated with new data.
 *
 * void update(std::string input);
 *		Precondition: Hash value is updated with all of input.
 *
 * void finish(void);
 *		Precondition: No more than 2^31-1 Gb of data should have been
 *			inputted to update function.
 *		Postcondition: Padding is added to remaining data, and is hashed
 *			on the rest of the message hash value.
 *
 * void reset(void);
 *		Postcondition: Each WORD of m_h (hash value) is set to its
 *			initial value. Each index of m_data_buf, and m_buf_fill_amt
 *			and m_total_fill_amt variables are set to their default
 *			values (0). m_hash_done is set to false.
 *
 * void get_hash_val(WORD hval[8]) const;
 *		Precondition: finish function must be called, to complete the
 *			hashing process.
 *		Postcondition: 256-bit (or eight 32-bit WORDs) hash value is
 *			stored in hval.
 *
 * void get_hash_val(uint8_t hval[32]) const;
 *		Precondition: Same as above get_hash_val function.
 *		Postcondition: Same as above get_hash_val function.
 *
 * void get_hash_val(mpz_class &hval) const;
 *		Precondition: Same as above get_hash_val function.
 *		Postcondition: Same as above get_hash_val function.
 *
 * void process(uint8_t *input);
 *		Precondition: input needs to have at least 512-bits (64 bytes)
 *			of data to be hashed.
 *		Postcondition: One intermediate hash value is calculated by
 *			processing the data from input. This value replaces the
 *			current hash value.
 *
 * void process(void);
 *		Precondition: m_data_buf needs to be completely filled with
 *			data to be hashed.
 *		Postcondition: Calls above process function, passing m_data_buf
 *			as the input.
 *
 *****************************************************************/

class SHA256_Hash
{
	friend class PKCS1_MGF1;
	friend class PKCS1_OAEP_Enc;
	friend class PKCS1_OAEP_Dec;

	public:
		SHA256_Hash(void);

		void		update(uint8_t *input, size_t length);
		void		update(std::string input);

		void		finish(void);
		void		reset(void);

		void		get_hash_val(WORD hval[8]) const;
		void		get_hash_val(uint8_t hval[32]) const;
		void		get_hash_val(mpz_class &hval) const;

	private:

		void		process(uint8_t *input);
		void		process(void);

		WORD		m_h[8];				/* Hash value */

		uint8_t		m_data_buf[64];		/* Buffer for message (512 bits) */
		size_t		m_buf_fill_amt;
		uint64_t	m_total_fill_amt;

		bool		m_hash_done;
};

#endif		/* SHA256_H */
