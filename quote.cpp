/*

Copyright 2017 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * DO NOT USE THIS CODE AS A TEMPLATE FOR IMPLEMENTING REMOTE
 * ATTESTATION. This code short-circuits the RA process in order 
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation: 
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 *----------------------------------------------------------------------
 */

#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#else
#include "config.h"
#endif

#define PSE_SUPPORT 1
#if(defined(_WIN32)||defined(SGX_HW_SIM))
#define PSE_SUPPORT 1
#endif

#include "EnclaveQuote_u.h"
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <intrin.h>
#include "getopt.h"
#else
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"

#define MAX_LEN 80

#ifndef WIN32
#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

int file_in_searchpath (const char *file, char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int debug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

void usage();

void usage () 
{
	fprintf(stderr, "usage: quote [ options ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte\n");
	fprintf(stderr, "                              ASCII hex string\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required\n\n");
	fprintf(stderr, "Optional:\n");
	fprintf(stderr, "  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte\n");
	fprintf(stderr, "                              ASCII hex string\n");
	fprintf(stderr, "  -e, --epid-gid           Get the EPID Group ID instead of a quote\n");
	fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
#ifdef PSE_SUPPORT
	fprintf(stderr, "  -m, --pse-manifest       Include the PSE manifest in the quote\n");
#endif
	fprintf(stderr, "  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -r                       Generate a nonce using RDRAND\n");
	fprintf(stderr, "\nRemote Attestation options:\n");
	fprintf(stderr, "  -1, --msg1               Generate msg1. Requires -p or -P.\n");
	fprintf(stderr, "  -p, --pubkey=HEXSTRING   The public key of the service provider as an\n");
	fprintf(stderr, "                              ASCII hex string.\n");
	fprintf(stderr, "  -P, --pubkey-file=FILE   File containing the public key of the service provider.\n");
	exit(1);
}

int main (int argc, char *argv[])
{
	sgx_launch_token_t token= { 0 };
	sgx_status_t status, sgxrv;
	sgx_enclave_id_t eid= 0;
	sgx_quote_t *quote;
	sgx_spid_t spid;
	sgx_report_t qe_report;
	int updated= 0;
	int sgx_support;
	uint32_t i;
	sgx_report_t report;
	uint32_t sz= 0;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	uint32_t n_epid_gid= 0xdeadbeef;
#ifndef _WIN32
	EVP_PKEY *service_public_key= NULL;
#endif
	sgx_ec256_public_t pubkey;
#ifdef PSE_SUPPORT
	sgx_ps_cap_t ps_cap;
	char *pse_manifest;
	size_t pse_manifest_sz;
#endif
#ifdef _WIN32
	LPTSTR b64quote = NULL;
	DWORD sz_b64quote = 0;
	LPTSTR b64manifest = NULL;
	DWORD sz_b64manifest = 0;
#else
	unsigned char  *b64quote= NULL;
# ifdef PSE_SUPPORT
	unsigned char *b64manifest = NULL;
# endif
#endif
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
	sgx_quote_nonce_t nonce;

	char flag_manifest = 0;
	char flag_nonce= 0;
	char flag_spid= 0;
	char flag_epid= 0;
	char flag_msg1= 0;
	char flag_pubkey= 0;

	static struct option long_opt[] =
	{
		{"help",		no_argument, 		0, 'h'},
		{"epid-gid",	no_argument,		0, 'e'},
#ifdef PSE_SUPPORT
		{"pse-manifest",	no_argument,	0, 'm'},
#endif
		{"nonce",		required_argument,	0, 'n'},
		{"nonce-file",	required_argument,	0, 'N'},
		{"rand-nonce",  no_argument,        0, 'r'},
		{"spid",		required_argument,	0, 's'},
		{"spid-file",	required_argument,	0, 'S'},
		{"linkable",	no_argument,		0, 'l'},
		{"msg1",		no_argument,		0, '1'},
		{"pubkey",		required_argument,	0, 'p'},
		{"pubkey-file",	required_argument,	0, 'P'},
		{ 0, 0, 0, 0}
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index= 0;
		off_t sz;
		unsigned char *keydata;
		unsigned char keyin[64];

		c= getopt_long(argc, argv, "1N:P:S:ehlmn:p:rs:", long_opt, &opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case '1':
			++flag_msg1;
			break;
		case 'N':
			if ( ! from_hexstring_file((unsigned char *) &nonce, optarg, 16)) {
				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			++flag_nonce;

			break;
		case 'P':
			if ( ! key_load_file(&service_public_key, optarg, KEY_PUBLIC) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("load_key_from_file");
				exit(1);
			} 

			if ( ! key_to_sgx_ec256(&pubkey, service_public_key) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("key_to_sgx_ec256");
				exit(1);
			}

			++flag_pubkey;

			break;
		case 'S':
			if ( ! from_hexstring_file((unsigned char *) &spid, optarg, 16)) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++flag_spid;

			break;
		case 'e':
			++flag_epid;
			break;
		case 'l':
			linkable= SGX_LINKABLE_SIGNATURE;
			break;
#ifdef PSE_SUPPORT
		case 'm':
			flag_manifest = 1;
			break;
#endif
		case 'n':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &nonce, (unsigned char *) optarg, 16) ) {
				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}

			++flag_nonce;

			break;
		case 'p':
			if ( ! from_hexstring((unsigned char *) keyin, (unsigned char *) optarg, 64)) {
				fprintf(stderr, "key must be 128-byte hex string\n");
				exit(1);
			}

			/* Reverse the byte stream to make a little endien style value */
			for(i= 0; i< 32; ++i) pubkey.gx[i]= keyin[31-i];
			for(i= 0; i< 32; ++i) pubkey.gy[i]= keyin[63-i];
			++flag_pubkey;

			break;
		case 'r':
			for(i= 0; i< 2; ++i) {
				int retry= 10;
				unsigned char ok= 0;
				uint64_t *np= (uint64_t *) &nonce;

				while ( !ok && retry ) ok= _rdrand64_step(&np[i]);
				if ( ok == 0 ) {
					fprintf(stderr, "nonce: RDRAND underflow\n");
					exit(1);
				}
			}
			++flag_nonce;
			break;
		case 's':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &spid, (unsigned char *) optarg, 16) ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++flag_spid;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	if ( flag_msg1 && ! flag_pubkey ) {
		fprintf(stderr, "public key required. Use one of --pubkey or --pubkey-file \n");
		return 1;
	}

	if ( ! flag_spid && ! flag_epid ) {
		fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
		return 1;
	}

	/* Can we run SGX? */

#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		fprintf(stderr, "This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	} 
#endif

	/* Launch the enclave */

#ifdef _WIN32
	status = sgx_create_enclave("EnclaveQuote.signed.dll", SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if (status != SGX_SUCCESS) {
		fprintf(stderr, "sgx_create_enclave: EnclaveQuote.signed.dll: %08x\n",
			status);
		return 1;
	}
#else
	status = sgx_create_enclave_search("EnclaveQuote.signed.so", SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: EnclaveQuote.signed.so: %08x\n",
			status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}
#endif

	/* Platform services info */
#ifdef PSE_SUPPORT
	if (flag_manifest) {
		status = sgx_get_ps_cap(&ps_cap);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "sgx_get_ps_cap: %08x\n", status);
			return 1;
		}

		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest_size: %08x\n",
				status);
			return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest: %08x\n",
				status);
			return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
				sgxrv);
			return 1;
		}
	}
#endif

	/* Get our quote */

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_init_quote: %08x\n", status);
		return 1;
	}

	/* Did they ask for just the EPID? */
	if ( flag_epid ) {
		printf("%08x\n", *(uint32_t *)epid_gid);
		exit(0);
	}

	status= get_report(eid, &sgxrv, &report, &target_info);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "get_report: %08x\n", status);
		return 1;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_report: %08x\n", sgxrv);
		return 1;
	}

	status= sgx_calc_quote_size(NULL, 0, &sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_calc_quote_size: %08x\n", status);
		return 1;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	if ( flag_msg1 ) {
		sgx_ra_context_t ctx= 0;
		sgx_ra_msg1_t msg1;

		/*
		 * WARNING! Normally, the public key would be hardcoded into the
		 * enclave, not passed in as a parameter. Hardcoding prevents
		 * the enclave using an unauthorized key.
		 *
		 * This is diagnostic/test application, however, so we need
		 * the flexibility of a dynamically assigned key.
		 */

		/* Executes an ECALL that runs sgx_ra_init() */

		status= enclave_ra_init(eid, &sgxrv, pubkey, 0, &ctx);
		if ( status != SGX_SUCCESS ) {
			fprintf(stderr, "enclave_ra_init: %08x\n", status);
			return 1;
		}
		if ( sgxrv != SGX_SUCCESS ) {
			fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
			return 1;
		}

		/* Get msg1 */

		status= sgx_ra_get_msg1(ctx, eid, sgx_ra_get_ga, &msg1);
		if ( status != SGX_SUCCESS ) {
			fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
			return 1;
		}

		print_hexstring(stdout, &msg1, sizeof(msg1));
		printf("\n");

		exit(0);
	}

	memset(quote, 0, sz);
	status= sgx_get_quote(&report, linkable, &spid,
		(flag_nonce) ? &nonce : NULL,
		NULL, 0,
		(flag_nonce) ? &qe_report : NULL, 
		quote, sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_quote: %08x\n", status);
		return 1;
	}

	/* Print our quote */

#ifdef _WIN32
	// We could also just do ((4 * sz / 3) + 3) & ~3
	// but it's cleaner to use the API.

	if (CryptBinaryToString((LPTSTR) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, NULL, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 1;
	}

	b64quote = malloc(sz_b64quote);
	if (CryptBinaryToString((LPTSTR) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, b64quote, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 1;
	}

	if (flag_manifest) {
		if (CryptBinaryToString((LPTSTR)pse_manifest, pse_manifest_sz, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 1;
		}

		b64manifest = malloc(sz_b64manifest);
		if (CryptBinaryToString((LPTSTR)pse_manifest, pse_manifest_sz, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64manifest, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 1;
		}
	}
#else
	b64quote= base64_encode((unsigned char *) quote, sz);
#ifdef PSE_SUPPORT
	if (flag_manifest) {
		b64manifest= base64_encode((unsigned char *) pse_manifest, pse_manifest_sz);
	}
# endif
#endif

	printf("{\n");
	printf("\"isvEnclaveQuote\":\"%s\"", b64quote);
	if ( flag_nonce ) {
		printf(",\n\"nonce\":\"");
		print_hexstring(stdout, &nonce, 16);
		printf("\"");
	}
#ifdef PSE_SUPPORT
	if (flag_manifest) {
		printf(",\n\"pseManifest\":\"%s\"", b64manifest);	
	}
#endif
	printf("\n}\n");

#ifdef SGX_HW_SIM
	fprintf(stderr, "WARNING! Built in h/w simulation mode. This quote will not be verifiable.\n");
#endif

}

/*
 * Search for the enclave file and then try and load it.
 */

#ifndef _WIN32
sgx_status_t sgx_create_enclave_search (const char *filename, const int debug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) 
		return sgx_create_enclave(filename, debug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, debug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, debug, token, updated, eid, attr);
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, debug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, debug, token, updated, eid, attr);

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, debug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len);
			rem= len-lp-1;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}

#endif
