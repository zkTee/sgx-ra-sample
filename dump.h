#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>

void print_hex(uint8_t buf[], int x) {
    int i;
    for (i = 0; i < x; i++)
    {
        // if (i > 0) printf(":");
        printf("%02X", buf[i]);
    }
    printf("\n");
}

void dump_report_body(sgx_report_body_t& report_body) {
	fprintf(stdout, "###report body: ");

	fprintf(stdout, "svn: ");
	print_hex(report_body.cpu_svn.svn, SGX_CPUSVN_SIZE); 
	fprintf(stdout, "misc_select: %d", report_body.misc_select);  
	fprintf(stdout, "reserved1: ");
	print_hex(report_body.reserved1, SGX_REPORT_BODY_RESERVED1_BYTES);
	fprintf(stdout, "isv_ext_prod_id: ");
	print_hex(report_body.isv_ext_prod_id, SGX_ISVEXT_PROD_ID_SIZE);
	fprintf(stdout, "attributes.flags / xfrm : %ld / %ld\n", report_body.attributes.flags, report_body.attributes.xfrm);
	fprintf(stdout, "mr_enclave: ");
	print_hex(report_body.mr_enclave.m, SGX_HASH_SIZE);
	fprintf(stdout, "reserved2: ");
	print_hex(report_body.reserved2, SGX_REPORT_BODY_RESERVED2_BYTES);
	fprintf(stdout, "mr_signer: ");
	print_hex(report_body.mr_signer.m, SGX_HASH_SIZE);
	fprintf(stdout, "reserved3: ");
	print_hex(report_body.reserved3, SGX_REPORT_BODY_RESERVED3_BYTES);
	fprintf(stdout, "config_id: ");
	print_hex(report_body.config_id, SGX_CONFIGID_SIZE);
	fprintf(stdout, "isv_prod_id: %d", report_body.isv_prod_id);  
	fprintf(stdout, "isv_svn: %d", report_body.isv_svn);  
	fprintf(stdout, "config_svn: %d", report_body.config_svn);  
	fprintf(stdout, "reserved4: ");
	print_hex(report_body.reserved4, SGX_REPORT_BODY_RESERVED4_BYTES);
	fprintf(stdout, "isv_family_id: ");
	print_hex(report_body.isv_family_id, SGX_ISV_FAMILY_ID_SIZE);
	fprintf(stdout, "report_data: ");
	print_hex(report_body.report_data.d, SGX_REPORT_DATA_SIZE);

    fprintf(stdout, "\n");
}

void dump_report(sgx_report_t *report) {
	fprintf(stdout, "#report: ");
	fprintf(stdout, "mac: ");
	print_hex(report->mac, SGX_MAC_SIZE);
	fprintf(stdout, "key_id: ");
	print_hex(report->key_id.id, SGX_KEYID_SIZE); 
    
	dump_report_body(report->body);

    fprintf(stdout, "\n");
}

void dump_quote(sgx_quote_t* quote) {
	fprintf(stdout, "quote: ");

	fprintf(stdout, "version: %d\n", quote->version);  
	fprintf(stdout, "sign_type: %d\n", quote->sign_type);  
	fprintf(stdout, "epid_group_id: %hhn\n", quote->epid_group_id);  
	fprintf(stdout, "qe_svn: %d\n", quote->qe_svn);  
	fprintf(stdout, "pce_svn: %d\n", quote->pce_svn);  
	fprintf(stdout, "xeid: %d\n", quote->xeid);  
	fprintf(stdout, "basename: ");
	print_hex(quote->basename.name, 32);
	fprintf(stdout, "signature_len: %d\n", quote->signature_len);  
	fprintf(stdout, "xeid: %d", quote->xeid);  
	print_hex(quote->signature, 4);

    dump_report_body(quote->report_body);

    fprintf(stdout, "\n");
}

// Attestation Evidence Payload
void dump_aep(sgx_quote_t* quote, uint32_t flags, sgx_quote_nonce_t nonce, uint32_t sz) {
	char  *b64quote= base64_encode((char *) quote, sz);
	if ( b64quote == NULL ) {
		eprintf("Could not base64 encode quote\n");
	}

	printf("{\n");
	printf("\"isvEnclaveQuote\":\"%s\"", b64quote);
	if ( flags & 0x02 ) {
		printf(",\n\"nonce\":\"");
		print_hexstring(stdout, &nonce, 16);
		printf("\"");
	}

	printf("\n}\n");

	free(b64quote);
}