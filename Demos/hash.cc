/**
 * File: hash.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/20/19
 *
 * Description:
 *		- Hashes the command line arguments (after the first one) that the user
 *			passes to the program.
 *
 * Compile: make hash
 */

#include <iostream>
#include <string>
#include <stdint.h>

#include "../SHA256/sha256.h"

using namespace std;

int main(int argc, const char *argv[])
{
	SHA256_Hash		hash;
	string			tmp_str;
	uint8_t			hval[32];

	// Update the hash with each command line argument (after first)
	for (int i = 1; i < argc; i++)
	{
		tmp_str = argv[i];
		hash.update(tmp_str);
	}

	// Finish hashing process and get hash value
	hash.finish();
	hash.get_hash_val(hval);

	// Print hash value to screen
	for (int i = 0; i < 32; i++)
	{
		if (hval[i] < 0x10) cout << "0";
		cout << hex << static_cast <unsigned int> (hval[i]);
	}
	cout << endl;

	return 0;
}
