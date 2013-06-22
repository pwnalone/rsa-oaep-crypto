/**
 * File: data_conv_prims.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the functions defined in data_conv_prims.h header file.
 */

#include "data_conv_prims.h"

int I2OSP(uint8_t octet_str[], unsigned int i, size_t length)
{
	mpz_class tmp_i_val (i);
	return I2OSP(octet_str, tmp_i_val, length);
}

int I2OSP(uint8_t octet_str[], mpz_class i, size_t length)
{
	int			index_c = 0;
	mpz_class	len_test, tmp_byte;

	// Test that i can fit in length octets (bytes)
	mpz_ui_pow_ui(len_test.get_mpz_t(), 256LU, length);
	if (i >= len_test) return 1;

	/* Divide i value into it's individual
	   bytes and store them in octet_str */
	while (i > 0)
	{
		tmp_byte = (i % 256LU);
		octet_str[length - 1 - index_c] = tmp_byte.get_ui();
		i /= 256LU;

		index_c++;
	}

	// Fill unfilled, leading octets with hex value 0x00
	memset(octet_str, 0x00, length - index_c);

	return 0;
}

int OS2IP(unsigned int &i, uint8_t octet_str[], size_t length)
{
	if (length > sizeof(int)) return 1;

	mpz_class tmp_i_val (i);

	/* Call OS2IP overloaded function on a GMP
	   integer and convert it to an unsigned integer */
	OS2IP(tmp_i_val, octet_str, length);
	i = tmp_i_val.get_ui();

	return 0;
}

int OS2IP(mpz_class &i, uint8_t octet_str[], size_t length)
{
	mpz_class tmp_shift;

	i = 0;

	// Convert the octet string to a GMP integer
	for (int j = length - 1; j >= 0; j--)
	{
		mpz_ui_pow_ui(tmp_shift.get_mpz_t(), 256LU, length - 1 - j);
		i += (tmp_shift * octet_str[j]);
	}

	return 0;
}
