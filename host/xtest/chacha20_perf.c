/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ta_chacha20_perf.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <time.h>
#include <unistd.h>

#include "crypto_common.h"
#include "xtest_helpers.h"

/*
 * Type of buffer used for the performance tests
 *
 * BUFFER_UNSPECIFIED		test did not specify target buffer to use
 * BUFFER_SHM_ALLOCATED		buffer allocated in TEE SHM.
 */
enum buffer_types {
	BUFFER_UNSPECIFIED = 0,
	BUFFER_SHM_ALLOCATED,
};

static enum buffer_types input_buffer = BUFFER_UNSPECIFIED;
static enum buffer_types output_buffer = BUFFER_UNSPECIFIED;

static const char *buf_type_str(int buf_type)
 {
	static const char ns_alloc[] = "Non secure memory";
	static const char inval[] = "UNEXPECTED";

	switch (buf_type) {
	case BUFFER_SHM_ALLOCATED:
		return ns_alloc;
	default:
		return inval;
	}
}

/*
 * TEE client stuff
 */

static TEEC_Context ctx;
static TEEC_Session sess;
/*
 * in_shm and out_shm are both IN/OUT to support dynamically choosing
 * in_place == 1 or in_place == 0.
 */
static TEEC_SharedMemory in_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};
static TEEC_SharedMemory out_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};

static void errx(const char *msg, TEEC_Result res, uint32_t *orig)
{
	fprintf(stderr, "%s: 0x%08x", msg, res);
	if (orig)
		fprintf(stderr, " (orig=%d)", (int)*orig);
	fprintf(stderr, "\n");
	exit (1);
}

static void check_res(TEEC_Result res, const char *errmsg, uint32_t *orig)
{
	if (res != TEEC_SUCCESS)
		errx(errmsg, res, orig);
}

static void open_ta(void)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = TA_AES_PERF_UUID;
	uint32_t err_origin = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	check_res(res, "TEEC_InitializeContext", NULL);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	check_res(res, "TEEC_OpenSession", &err_origin);
}

/*
 * Statistics
 *
 * We want to compute min, max, mean and standard deviation of processing time
 */

struct statistics {
	int n;
	double m;
	double M2;
	double min;
	double max;
	int initialized;
};

/* Take new sample into account (Knuth/Welford algorithm) */
static void update_stats(struct statistics *s, uint64_t t)
{
	double x = (double)t;
	double delta = x - s->m;

	s->n++;
	s->m += delta/s->n;
	s->M2 += delta*(x - s->m);
	if (!s->initialized) {
		s->min = s->max = x;
		s->initialized = 1;
	} else {
		if (s->min > x)
			s->min = x;
		if (s->max < x)
			s->max = x;
	}
}

static double stddev(struct statistics *s)
{
	if (s->n < 2)
		return NAN;
	return sqrt(s->M2/s->n);
}

static const char *mode_str(uint32_t mode)
{
	switch (mode) {
	case TA_CHACHA20_POLY1305:
		return "POLY1305";
	default:
		return "???";
	}
}

#define _TO_STR(x) #x
#define TO_STR(x) _TO_STR(x)

static void usage(const char *progname, int keysize, int mode, size_t size,
		  size_t unit, int warmup, unsigned int l, unsigned int n)
{
	fprintf(stderr, "Usage: %s [-h]\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-i] [-k SIZE]", progname);
	fprintf(stderr, " [-l LOOP] [-m MODE] [-n LOOP] [-r|--no-inited] [-s SIZE]");
	fprintf(stderr, " [-v [-v]] [-w SEC]");
	fprintf(stderr, "\n");
	fprintf(stderr, "CHACHA20 performance testing tool for OP-TEE\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -d            Test CHACHA20 decryption instead of encryption\n");
	fprintf(stderr, "  -h|--help     Print this help and exit\n");
	fprintf(stderr, "  -i|--in-place Use same buffer for input and output (decrypt in place)\n");
	fprintf(stderr, "[TODO]-k SIZE       Key size in bits: 256 [%u]\n", keysize);
	fprintf(stderr, "  -l LOOP       Inner loop iterations [%u]\n", l);
	fprintf(stderr, "  -m MODE       CHACHA20 mode: POLY1305 [%s]\n", mode_str(mode));
	fprintf(stderr, "  -n LOOP       Outer test loop iterations [%u]\n", n);
	fprintf(stderr, "  --not-inited  Do not initialize input buffer content.\n");
	fprintf(stderr, "  -r|--random   Get input data from /dev/urandom (default: all zeros)\n");
	fprintf(stderr, "  -s SIZE       Test buffer size in bytes [%zu]\n", size);
	fprintf(stderr, "  -u UNIT       Divide buffer in UNIT-byte increments (+ remainder)\n");
	fprintf(stderr, "                (0 to ignore) [%zu]\n", unit);
	fprintf(stderr, "  -v            Be verbose (use twice for greater effect)\n");
	fprintf(stderr, "  -w|--warmup SEC  Warm-up time in seconds: execute a busy loop before\n");
	fprintf(stderr, "                   the test to mitigate the effects of cpufreq etc. [%u]\n", warmup);
}

static void allocate_shm(TEEC_SharedMemory *shm, size_t sz)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	shm->buffer = NULL;
	shm->size = sz;
	res = TEEC_AllocateSharedMemory(&ctx, shm);
	check_res(res, "TEEC_AllocateSharedMemory", NULL);
}

/* initial test buffer allocation (eventual registering to TEEC) */
static void alloc_buffers(size_t sz, int in_place, int verbosity)
{
	(void)verbosity;

	if (input_buffer == BUFFER_SHM_ALLOCATED)
		allocate_shm(&in_shm, sz);

	if (in_place)
		return;

	if (output_buffer == BUFFER_SHM_ALLOCATED)
		allocate_shm(&out_shm, sz);
}

static void free_shm(int in_place)
{
	(void)in_place;

	if (input_buffer == BUFFER_SHM_ALLOCATED &&
	    output_buffer == BUFFER_SHM_ALLOCATED) {
		TEEC_ReleaseSharedMemory(&in_shm);
		TEEC_ReleaseSharedMemory(&out_shm);
		return;
	}
}

static ssize_t read_random(void *in, size_t rsize)
{
	static int rnd;
	ssize_t s = 0;

	if (!rnd) {
		rnd = open("/dev/urandom", O_RDONLY);
		if (rnd < 0) {
			perror("open");
			return 1;
		}
	}
	s = read(rnd, in, rsize);
	if (s < 0) {
		perror("read");
		return 1;
	}
	if ((size_t)s != rsize) {
		printf("read: requested %zu bytes, got %zd\n", rsize, s);
	}

	return 0;
}

static void get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
}

static uint64_t timespec_to_ns(struct timespec *ts)
{
	return ((uint64_t)ts->tv_sec * 1000000000) + ts->tv_nsec;
}

static uint64_t timespec_diff_ns(struct timespec *start, struct timespec *end)
{
	return timespec_to_ns(end) - timespec_to_ns(start);
}

static void prepare_key(int decrypt, int keysize, int mode)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_origin = 0;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t cmd = TA_CHACHA20_PERF_CMD_PREPARE_KEY;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = decrypt;
	op.params[0].value.b = keysize;
	op.params[1].value.a = mode;
	res = TEEC_InvokeCommand(&sess, cmd, &op,
				 &ret_origin);
	check_res(res, "TEEC_InvokeCommand", &ret_origin);
}

static void do_warmup(int warmup)
{
	struct timespec t0 = { };
	struct timespec t = { };
	int i = 0;

	get_current_time(&t0);
	do {
		for (i = 0; i < 100000; i++)
			;
		get_current_time(&t);
	} while (timespec_diff_ns(&t0, &t) < (uint64_t)warmup * 1000000000);
}

static const char *yesno(int v)
{
	return (v ? "yes" : "no");
}

static double mb_per_sec(size_t size, double usec)
{
	return (1000000000/usec)*((double)size/(1024*1024));
}

static void feed_input(void *in, size_t size, int random)
{
	if (random)
		read_random(in, size);
	else
		memset(in, 0, size);
}

static void run_feed_input(void *in, size_t size, int random)
{
	feed_input(in, size, random);
	return;
}


void chacha20_perf_run_test(int mode, int keysize, int decrypt, size_t size,
				size_t unit, unsigned int n, unsigned int l,
				int input_data_init, int in_place, int warmup,
				int verbosity)
{
	struct statistics stats = { };
	struct timespec ts = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	int n0 = n;
	double sd = 0;
	uint32_t cmd = TA_CHACHA20_PERF_CMD_PROCESS;

	if (input_buffer == BUFFER_UNSPECIFIED)
		input_buffer = BUFFER_SHM_ALLOCATED;

	if (output_buffer == BUFFER_UNSPECIFIED)
		output_buffer = BUFFER_SHM_ALLOCATED;

	if (clock_getres(CLOCK_MONOTONIC, &ts) < 0) {
		perror("clock_getres");
		return;
	}
	vverbose("Clock resolution is %jd ns\n",
		 (intmax_t)ts.tv_sec * 1000000000 + ts.tv_nsec);

	vverbose("input test buffer:  %s\n", buf_type_str(input_buffer));
	vverbose("output test buffer: %s\n", buf_type_str(output_buffer));

	open_ta();
	prepare_key(decrypt, keysize, mode);

	alloc_buffers(size, in_place, verbosity);
	if (input_data_init == CRYPTO_USE_ZEROS)
		run_feed_input(in_shm.buffer, size, 0);

	/* Using INOUT to handle the case in_place == 1 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.size = size;
	op.params[1].memref.parent = in_place ? &in_shm : &out_shm;
	op.params[1].memref.size = size;
	op.params[2].value.a = l;
	op.params[2].value.b = unit;

	verbose("Starting test: %s, %scrypt, keysize=%u bits, size=%zu bytes, ",
		mode_str(mode), (decrypt ? "de" : "en"), keysize, size);
	verbose("random=%s, ", yesno(input_data_init == CRYPTO_USE_RANDOM));
	verbose("in place=%s, ", yesno(in_place));
	verbose("inner loops=%u, loops=%u, warm-up=%u s, ", l, n, warmup);
	verbose("unit=%zu\n", unit);

	if (warmup)
		do_warmup(warmup);

	while (n-- > 0) {
		TEEC_Result res = TEEC_ERROR_GENERIC;
		uint32_t ret_origin = 0;
		struct timespec t0 = { };
		struct timespec t1 = { };

		if (input_data_init == CRYPTO_USE_RANDOM)
			run_feed_input(in_shm.buffer, size, 1);

		get_current_time(&t0);

		res = TEEC_InvokeCommand(&sess, cmd,
					 &op, &ret_origin);
		check_res(res, "TEEC_InvokeCommand", &ret_origin);

		get_current_time(&t1);

		update_stats(&stats, timespec_diff_ns(&t0, &t1));
		if (n % (n0 / 10) == 0)
			vverbose("#");
	}
	vverbose("\n");
	sd = stddev(&stats);
	printf("min=%gus max=%gus mean=%gus stddev=%gus (cv %g%%) (%gMiB/s)\n",
	       stats.min / 1000, stats.max / 1000, stats.m / 1000,
	       sd / 1000, 100 * sd / stats.m, mb_per_sec(size, stats.m));
	verbose("2-sigma interval: %g..%gus (%g..%gMiB/s)\n",
		(stats.m - 2 * sd) / 1000, (stats.m + 2 * sd) / 1000,
		mb_per_sec(size, stats.m + 2 * sd),
		mb_per_sec(size, stats.m - 2 * sd));
	free_shm(in_place);
}

#define NEXT_ARG(i) \
	do { \
		if (++i == argc) { \
			fprintf(stderr, "%s: %s: missing argument\n", \
				argv[0], argv[i - 1]); \
			return 1; \
		} \
	} while (0);

#define USAGE() usage(argv[0], keysize, mode, size, unit, warmup, l, n)

int chacha20_perf_runner_cmd_parser(int argc, char *argv[])
{
	int i = 0;
	/*
	* Command line parameters
	*/
	size_t size = 1024;	/* Buffer size (-s) */
	size_t unit = CRYPTO_DEF_UNIT_SIZE; /* Divide buffer (-u) */
	unsigned int n = CRYPTO_DEF_COUNT; /*Number of measurements (-n)*/
	unsigned int l = CRYPTO_DEF_LOOPS; /* Inner loops (-l) */
	int verbosity = CRYPTO_DEF_VERBOSITY;	/* Verbosity (-v) */
	int decrypt = 0;		/* Encrypt by default, -d to decrypt */
	int keysize = CHACHA20_POLY1305_256;	/* CHACHA20 key size (-k) */
	int mode = TA_CHACHA20_POLY1305;	/* CHACHA20 mode (-m) */
	/* Get input data from /dev/urandom (-r) */
	int input_data_init = CRYPTO_USE_ZEROS;
	/* Use same buffer for in and out (-i) */
	int in_place = 0;
	int warmup = CRYPTO_DEF_WARMUP;	/* Start with a 2-second busy loop (-w) */

	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			USAGE();
			return 0;
		}
	}
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d")) {
			decrypt = 1;
		} else if (!strcmp(argv[i], "--in-place") ||
			   !strcmp(argv[i], "-i")) {
			in_place = 1;
		} else if (!strcmp(argv[i], "-k")) {
			NEXT_ARG(i);
			keysize = atoi(argv[i]);
			if (keysize != CHACHA20_POLY1305_256) {
				fprintf(stderr, "%s: invalid key size\n",
					argv[0]);
				USAGE();
				return 1;
			}
		} else if (!strcmp(argv[i], "-l")) {
			NEXT_ARG(i);
			l = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-m")) {
			NEXT_ARG(i);
			if (!strcasecmp(argv[i], "POLY1305"))
				mode = TA_CHACHA20_POLY1305;
			else {
				fprintf(stderr, "%s, invalid mode\n",
					argv[0]);
				USAGE();
				return 1;
			}
		} else if (!strcmp(argv[i], "-n")) {
			NEXT_ARG(i);
			n = atoi(argv[i]);
		} else if (!strcmp(argv[i], "--random") ||
			   !strcmp(argv[i], "-r")) {
			if (input_data_init == CRYPTO_NOT_INITED) {
				perror("--random is not compatible with --not-inited\n");
				USAGE();
				return 1;
			}
			input_data_init = CRYPTO_USE_RANDOM;
		} else if (!strcmp(argv[i], "--not-inited")) {
			if (input_data_init == CRYPTO_USE_RANDOM) {
				perror("--random is not compatible with --not-inited\n");
				USAGE();
				return 1;
			}
			input_data_init = CRYPTO_NOT_INITED;
		} else if (!strcmp(argv[i], "-s")) {
			NEXT_ARG(i);
			size = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-u")) {
			NEXT_ARG(i);
			unit = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-v")) {
			verbosity++;
		} else if (!strcmp(argv[i], "--warmup") ||
			   !strcmp(argv[i], "-w")) {
			NEXT_ARG(i);
			warmup = atoi(argv[i]);
		} else {
			fprintf(stderr, "%s: invalid argument: %s\n",
				argv[0], argv[i]);
			USAGE();
			return 1;
		}
	}

	if (size & (16 - 1)) {
		fprintf(stderr, "invalid buffer size argument, must be a multiple of 16\n\n");
		USAGE();
		return 1;
	}


	chacha20_perf_run_test(mode, keysize, decrypt, size, unit, n, l,
			  input_data_init, in_place, warmup, verbosity);

	return 0;
}
