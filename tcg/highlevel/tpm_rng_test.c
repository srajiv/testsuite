
/*
 * TPM RNG test
 *
 * Write some random data from the TPM's RNG to stdout, suitable
 * for passing to rngtest, a FIPS certified random number tester, which
 * is available here: http://sourceforge.net/projects/gkernel/
 *
 * Usage: tpm_rng_test [-s]
 *  -s: Seed the TPM's RNG with 4 bytes of data from gettimeofday()
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

#include <tss/platform.h>
#include <tss/tcpa_defines.h>
#include <tss/tcpa_typedef.h>
#include <tss/tcpa_struct.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>

#include <trousers/trousers.h>

#include "../common/common.h"

#define ERR(x, ...)	fprintf(stderr, x, ##__VA_ARGS__)

#define RNG_BLOCK_SIZE	((20000 / 8) + 32)
#define LOOPS		10
#define RANDOM_DEVICE	"/dev/urandom"
#define SEED_SIZE	64

int
main(int argc, char **argv)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_HKEY hSRK;
	TSS_RESULT result;
	UINT32 rnd_len, i;
	BYTE *rnd;
	size_t nmembers;
	int rc, seed = 0;

	if (argv[1] && !strncmp(argv[1], "-s", 2))
		seed = 1;

	if ((result = connect_load_all(&hContext, &hSRK, &hTPM))) {
		ERR("connect_load_all failed: %s.", Trspi_Error_String(result));
		return 1;
	}

	if (seed) {
		BYTE entropy[64];
		FILE *f;

		if ((f = fopen(RANDOM_DEVICE, "r")) == NULL) {
			ERR("Opening device failed: %s.", RANDOM_DEVICE);
			Tspi_Context_Close(hContext);
			return 1;
		}

		if ((rc = fread(entropy, SEED_SIZE, 1, f)) != 1) {
			ERR("Reading from device %s failed: %s.", RANDOM_DEVICE, strerror(errno));
			fclose(f);
			Tspi_Context_Close(hContext);
			return 1;
		}
		fclose(f);

		if ((result = Tspi_TPM_StirRandom(hTPM, SEED_SIZE, entropy))) {
			ERR("Tspi_TPM_StirRandom failed: %s.", Trspi_Error_String(result));
			Tspi_Context_Close(hContext);
			return 1;
		}
	}

	rnd_len = RNG_BLOCK_SIZE;
	for (i = 0; i < LOOPS; i++) {
		if ((result = Tspi_TPM_GetRandom(hTPM, rnd_len, &rnd))) {
			ERR("Tspi_TPM_GetRandom failed: %s.", Trspi_Error_String(result));
			Tspi_Context_Close(hContext);
			return 1;
		}

		if ((nmembers = fwrite(rnd, rnd_len, 1, stdout)) != 1) {
			ERR("fwrite failed: %s.", strerror(errno));
			Tspi_Context_FreeMemory(hContext, rnd);
			Tspi_Context_Close(hContext);
			return 1;
		}

		Tspi_Context_FreeMemory(hContext, rnd);
	}

	Tspi_Context_Close(hContext);

	return 0;
}
