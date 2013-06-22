/**
 * File: mask.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/20/13
 *
 * Description:
 *		- Generates a mask given a mask length and seed input (command
 *			line arguments).
 *
 * Compile: make mask
 */

#include <cstdlib>
#include <iostream>
#include <string>
#include <stdint.h>

#include "../MGF1/pkcs1_mgf1.h"

using namespace std;

int main(int argc, const char *argv[])
{
	// Check for incorrect usage
	if (argc < 2)
	{
		cout << "Usage: " << argv[0] << " ";
		cout << "length [seed] [...]" << endl;
		return 1;
	}

	PKCS1_MGF1		mgf;
	size_t			length;
	string			tmp_str;

	uint8_t			*mask_val;

	// Set the length of the mask to create
	length = strtoul(argv[1], NULL, 0);
	mgf.set_mask_len(length);

	// Read in the seed input (command line arguments after second)
	for (int i = 2; i < argc; i++)
	{
		tmp_str = argv[i];
		mgf.update_seed(tmp_str);
	}

	mgf.finish_mask();

	// Get the mask value
	mask_val = new uint8_t[length];
	mgf.get_mask(mask_val);

	// Display the mask value in hexadecimal
	for (int i = 0; i < length; i++)
	{
		if (mask_val[i] < 0x10) cout << "0";
		cout << hex << static_cast <unsigned int> (mask_val[i]);
	}
	cout << endl;

	// Free all allocated memory
	mgf.clear_mgf();

	delete[] mask_val;
	mask_val = NULL;

	return 0;
}
