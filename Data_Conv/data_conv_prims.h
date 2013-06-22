/**
 * File: data_conv_prims.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines functions for converting between GMP multiple precision
 *			integers and octet strings, and between regular integers and
 *			octet strings.
 */

#ifndef DATA_CONV_PRIMS_H
#define DATA_CONV_PRIMS_H

#include <gmpxx.h>
#include <stdint.h>

/**
 * Precondition: octet_str has at least length bytes (octets) of
 *		memory.
 * Postcondition: i is separated into its individual bytes and
 *		stored in octet_str from most significant byte to least
 *		significant. Returns 0 upon success and 1 upon failure.
 */
int I2OSP(uint8_t octet_str[], unsigned int i, size_t length);

/**
 * Precondition: Same as above I2OSP function.
 * Postcondition: Same as above I2OSP function.
 */
int I2OSP(uint8_t octet_str[], mpz_class i, size_t length);

/**
 * Precondition: octet_str has length bytes (octets) of valid
 *		uint8_t values. length can't be larger than the size of
 *		an int.
 * Postcondition: octet_str is converted to an unsigned integer by
 *		essentially concatenating the octets.
 */
int OS2IP(unsigned int &i, uint8_t octet_str[], size_t length);

/**
 * Precondition: octet_str hash length bytes (octets) of valid
 *		uint8_t values.
 * Postcondition: octet_str is converted to a GMP integer by
 *		essentially concatenating the octets.
 */
int OS2IP(mpz_class &i, uint8_t octet_str[], size_t length);

#endif		/* DATA_CONV_PRIMS_H */
