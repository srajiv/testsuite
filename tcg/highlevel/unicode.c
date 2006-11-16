
/*
 * unicode test
 *
 * Using the trousers unicode functions, test a variety of strings, comparing them
 * to known good values
 *
 * (C) IBM Corp. 2006
 *
 * Kent E. Yoder
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "common.h"

#define ERR(x, ...)	fprintf(stderr, x "\n", ##__VA_ARGS__)

struct data
{
	BYTE *data;
	unsigned size;
};

struct data ascii_strings[] = {
	{ "", 0 },
	{ "localhost", 10 },
	{ "5683nft;4kl32fmy5p8o34myc8thjfilghf7oi!#$%^(*@&$^)_~`'\"fdf<>?/.x,xvz-=+_", 72 }
};

struct data utf16le_strings[] = {
	{ "\0\0", 2 },
	{ "l\0o\0c\0a\0l\0h\0o\0s\0t\0\0\0", 20 },
	{ "5\0006\0008\0003\0n\0f\0t\0;\0004\0k\0l\0003\0002\0f\0m\0y\0005\0p\0008\0o\0003\0004\0m\0y\0c\0008\0t\0h\0j\0f\0i\0l\0g\0h\0f\0007\0o\0i\0!\0#\0$\0%\0^\0(\0*\0@\0&\0$\0^\0)\0_\0~\0`\0\'\0\"\0f\0d\0f\0<\0>\0?\0/\0.\000x\0,\0x\0v\0z\0-\0=\0+\0_\0\0\0", 146 }
};

#define NUM_STRINGS 3

int
main(int argc, char **argv)
{
	unsigned i, size;
	BYTE *u;

	for (i = 0; i < NUM_STRINGS; i++) {
		size = ascii_strings[i].size;
		u = TestSuite_Native_To_UNICODE(ascii_strings[i].data, &size);

		if (size != utf16le_strings[i].size) {
			ERR("Size of string %u is bad", i);
			ERR("Actual (%u bytes):", size);
			print_hex(u, size);
			ERR("Expected (%u bytes):", utf16le_strings[i].size);
			print_hex(utf16le_strings[i].data, utf16le_strings[i].size);
			break;
		}

		if (memcmp(utf16le_strings[i].data, u, size)) {
			ERR("string %u doesn't match", i);
			ERR("Actual:");
			print_hex(u, size);
			ERR("Expected:");
			print_hex(utf16le_strings[i].data, size);
			break;
		}

		printf("Test %u: Success\n", i);
	}

	return 0;
}
