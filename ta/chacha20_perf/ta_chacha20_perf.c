/*
 * Copyright (c) 2020, Universita' di Modena e Reggio Emilia
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

#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <tee_ta_api.h>
#include <string.h>
#include <trace.h>

#include "ta_chacha20_perf.h"
#include "ta_chacha20_perf_priv.h"

#define CHECK(res, name, action) do {			\
		if ((res) != TEE_SUCCESS) {		\
			DMSG(name ": 0x%08x", (res));	\
			action				\
		}					\
	} while(0)

#define TAG_LEN	128

static uint8_t iv[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };

static TEE_OperationHandle crypto_op = NULL;
static uint32_t algo;

#if defined(CFG_CACHE_API)
static TEE_Result flush_memref_buffer(TEE_Param *param)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_CacheFlush(param->memref.buffer,
			     param->memref.size);
	CHECK(res, "TEE_CacheFlush(in)", return res;);
	return res;
}
#else
static __maybe_unused TEE_Result flush_memref_buffer(TEE_Param *param __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_CACHE_API */

TEE_Result cmd_process(uint32_t param_types,
		       TEE_Param params[TEE_NUM_PARAMS],
		       bool use_sdp)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int n = 0;
	int unit = 0;
	void *in = NULL;
	void *out = NULL;
	uint32_t insz = 0;
	uint32_t outsz = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE);

	TEE_Result (*do_update)(TEE_OperationHandle, const void *, uint32_t,
				void *, uint32_t *) = NULL;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	in = params[0].memref.buffer;
	insz = params[0].memref.size;
	out = params[1].memref.buffer;
	outsz = params[1].memref.size;
	n = params[2].value.a;
	unit = params[2].value.b;
	if (!unit)
		unit = insz;

	if (algo == TEE_ALG_CHACHA20_POLY1305)
		do_update = TEE_AEUpdate;
	else
		return TEE_ERROR_BAD_PARAMETERS;

	while (n--) {
		uint32_t i = 0;
		for (i = 0; i < insz / unit; i++) {
			res = do_update(crypto_op, in, unit, out, &outsz);
			CHECK(res, "TEE_AEUpdate", return res;);
			in  = (void *)((uintptr_t)in + unit);
			out = (void *)((uintptr_t)out + unit);
		}
		if (insz % unit) {
			res = do_update(crypto_op, in, insz % unit, out, &outsz);
			CHECK(res, "TEE_AEUpdate", return res;);
		}
	}

	return TEE_SUCCESS;
}

TEE_Result cmd_prepare_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
	TEE_Attribute attr = { };
	uint32_t mode = 0;
	uint32_t op_keysize = 0;
	uint32_t keysize = 0;
	const uint8_t *ivp = NULL;
	size_t ivlen = 0;
	static uint8_t cha_key[]  = { 0x80, 0x81, 0x82, 0x83, 0x84,
					0x85, 0x86, 0x87, 0x88, 0x89,
					0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
					0x8f, 0x90, 0x91, 0x92, 0x93,
					0x94, 0x95, 0x96, 0x97, 0x98,
					0x99, 0x9a, 0x9b, 0x9c, 0x9d,
					0x9e, 0x9f };
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	mode = params[0].value.a ? TEE_MODE_DECRYPT : TEE_MODE_ENCRYPT;
	keysize = params[0].value.b;
	op_keysize = keysize;

	switch (params[1].value.a) {
	case TA_CHACHA20_POLY1305:
		algo = TEE_ALG_CHACHA20_POLY1305;
		ivp = iv;
		ivlen = sizeof(iv);
		/* Check key size */
		if (keysize != CHACHA20_POLY1305_256)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cmd_clean_res();

	res = TEE_AllocateOperation(&crypto_op, algo, mode, op_keysize);
	CHECK(res, "TEE_AllocateOperation", return res;);

	/* TODO: we need a TEE_TYPE_CHACHA20 */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, keysize, &hkey);
	CHECK(res, "TEE_AllocateTransientObject", return res;);

	attr.attributeID = TEE_ATTR_SECRET_VALUE;
	attr.content.ref.buffer = cha_key;
	attr.content.ref.length = keysize / 8;

	res = TEE_PopulateTransientObject(hkey, &attr, 1);
	CHECK(res, "TEE_PopulateTransientObject", return res;);

	res = TEE_SetOperationKey(crypto_op, hkey);
	CHECK(res, "TEE_SetOperationKey", return res;);

	TEE_FreeTransientObject(hkey);

	return TEE_AEInit(crypto_op, ivp, ivlen, TAG_LEN, 0, 0);
}

void cmd_clean_res(void)
{
	if (crypto_op)
		TEE_FreeOperation(crypto_op);
}
