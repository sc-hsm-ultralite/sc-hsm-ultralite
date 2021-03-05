/**
 * SmartCard-HSM Ultra-Light Library
 *
 * Copyright (c) 2013. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the BSD 3-Clause License. You should have 
 * received a copy of the BSD 3-Clause License along with this program. 
 * If not, see <http://opensource.org/licenses/>
 *
 * @file sc-hsm-ultralite.c
 * @author Christoph Brunhuber
 * @brief Functions for RSA-2k signing of SHA-256
 *                  ECDSA-prime256 signing of SHA-256
 *                  Card Devices, Version 1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "utils.h"
#include "sc-hsm-ultralite.h"

/*
	This code implements "template-based" signing.
	A detached CMS signature file (Cryptographic Message Syntax, RFC 5652) is an ASN.1
	encoded data structure. It is a de facto standard (commonly used for signed emails S/MIME).
	To produce the data structure is a non trivial task. Mostly a huge crypto package like
	openssl or cryptlib is used to create the CMS.
	The steps to create a CMS detached signature file are as follows:
	Create a hash of the document to sign.
	Put that hash into the MessageDigest field of the SignedAttributes.
	Put the current UTC time into the SigningTime field of the SignedAttributes.
	Hash the SignedAttributes and create a signature of that hash.
	It turns out that a CMS signature file is fairly similar, even for different documents (i.e. different hashes).
	Specifically the MessageDigest, the SigningTime and the Signature itself are the dynamic
	fields, all other fields are static. Because a RSA signature from the same key always has
	the same size, the CMS signature file can be produced from a template by simply patching the 3
	fields. The needed cryptographic ciphers are, hashing (here SHA256) and the RSA private key
	operation. The RSA operation is actually running on the token (no crypto code required).
	In this specific case the raw RSA private key operation is used, so the PKCS#1.5 padding is also
	implemented here (trivial).
	The template itself is a small header + a valid CMS signature file (for an arbitrary document). It is stored as PKCS11 data on the token.
	The link between a private key and a template is the label.
	The template contains also a patch plan (offset of the fields which need to be changed).
	The patch plan is the mentioned header. See "typedef struct {..} Template_t" for details.
	The interface contains actually a single function (sign_hash) which returns the CMS signature file for a
	given document hash. The program uses ~2k heap memory and ~2k stack memory (not including the USB library).
	The template is cached internally for reuse. However it is also robust against a token change.
	
	This specific token supports both ECDSA and RSA.  This library also supports ECDSA (prime256v1 == secp256r1),
	with a few caveats.

	WARNINGS:

	The template works from the year 2013 until 2049 inclusive. Before the year 2050 the representation of the signing time
	year is 2 digits, starting with 2050 it uses 4 digits.

	The functions sign_hash and release_template are not thread safe. Further the signature passed back from sign_hash
	is invalidated by another sign_hash call. In other words, the caller must use the result or copy the result before
	calling sign_hash again. The sign_hash call and the usage of the signature data must be mutually exclusive.
	The function release_template should be called at the very end. Calling release_template is mandatory on an OS where 
	you do not have isolated processes and the OS does not automatically release task-allocated memory after task
	termination (e.g. WIN16)

	For performance reasons, sign_hash internally caches the last used template. If you need to sign multiple files with
	different keys (labels) you should sign the files with the first key, then the files with the second key
	and so on. Otherwise the template has to be loaded from the token for each file. The function sign_hash is robust against
	token changes.

	The exposed hash functions are thread safe as long as you use distinct contexts.
*/

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ************************ Template Helper Functions ****************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************

/* Warning: case sensitive */
static int FindLabel(const char *label, const uint8* buf, int len)
{
	int val, ix = 0;

#define ReturnIfTagIsNot(tag1, tag2)\
	if (ix >= len || buf[ix] != tag1 && buf[ix] != tag2)\
		return 0;\
	if (++ix >= len)\
		return 0;\
	val = buf[ix++];\
	if (val >= 0x80)\
		ix += 1 + (val & 0x7f); /* skip over length bytes */

/* SEQUENCE or CONT [0] */
	ReturnIfTagIsNot(0x30, 0xa0);
/*   SEQUENCE */
	ReturnIfTagIsNot(0x30, 0x30);
/*     UTF8String */
	ReturnIfTagIsNot(0x0c, 0x0c);
	if (val >= 0x80)
		return 0;  /* assume length < 128 */
	val += ix; /* end of UTF8String */
	if (val > len)
		return 0;
	/* compare passed label with label of file */
	while (ix < val && *label) {
		if (*label++ != buf[ix++]) /* case sensitive */
			return 0;
	}
	return ix == val && *label == 0;

#undef ReturnIfTagIsNot
}

static int FindFid(uint8 hi, uint8 lo, const uint8* buf, int len)
{
	int i;
	for (i = 0; i < len; i += 2) {
		if (buf[i] == hi && buf[i + 1] == lo)
			return i;
	}
	return -1;
}

/*
	Elementary files on the SmartCard-HSM from CardContact are addressed by a 16 bit unsigned integer,
	where the upper 8 bits (hi) indicate the type of file and the lower 8 bits (lo) the name.
	
	In most cases two file types are associated to each other. The link between these two file types
	is the name (where the name is the lower 8 bits). This is used, for example, to bind a data file
	(e.g. private key) with a data descriptor file.
	
	For example, file types 0xCCxx and 0xC4xx are associated with each other.	
	private keys:
	0xCC00 | lo .. private key 0 (never readable)
	0xCC03 | lo .. private key 1 (never readable)
	0xC400 | lo .. private key 0 descriptor
	0xC403 | lo .. private key 1 descriptor

	PKCS11 PIN protected data
	0xCD05 | lo .. data 0
	0xCD07 | lo .. data 1
	0xC905 | lo .. data 0 descriptor
	0xC907 | lo .. data 1 descriptor

	The function GetFids returns the key file identification (fid) in pKeyFid and the template fid in pTemplateFid.
	Because the template preparation is performed via PKCS11, the association between
	the key and the template is the label (you cannot specify the elementary file id
	with PKCS11, the ids are managed internally by the PKCS11 library).
	E.g.: We have a key "sign0" with fid 0xCC03 for the private data and 0xC403 for the descriptor.
	To find a key for a given label: enumerate through all 0xCCii files and open the associated
	0xC4ii descriptor file. Check if it has the proper label (e.g. "sign0").
	If found: enumerate through all 0xCDjj files and open the associated 0xC9jj descriptor file.
	Check if it has the same label.
	In case of success we have found a template associates with a key.
	Templates could be also used with PKCS11 without a crypto library.
	The approach in this library is much simpler, you do not even need a PKCS11 library, here it is managed
	on a lower level, but specific to the SC-HSM (CardContact) card.
*/
static int GetFids(const char *label, uint16 *pKeyFid, uint16 *pTemplateFid)
{
	uint8 list[2 * 128];
	uint16 sw1sw2;
	int rc, i;
	*pKeyFid = 0;
	*pTemplateFid = 0;
	/* - SmartCard-HSM: ENUMERATE OBJECTS */
	rc = SC_ProcessAPDU(
		0, 0x80,0x58,0x00,0x00,
		0, 0,
		list, sizeof(list),
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000 && sw1sw2 != 0x6282)
		return ERR_APDU;
	/* find key file id */
	for (i = 0; i < rc; i += 2) {
		if (list[i] == 0xCC && FindFid(0xC4, list[i + 1], list, rc) >= 0) {
			uint8 buf[256];
			int rc = SC_ReadFile(0xC400 | list[i + 1], 0, buf, sizeof(buf));
			if (rc > 0 && FindLabel(label, buf, rc)) {
				*pKeyFid = 0xCC00 | list[i + 1];
				break;
			}
		}
	}
	if (*pKeyFid == 0) {
		log_err("key '%s' not found", label);
		return ERR_KEY;
	}
	/* find template file id */
	for (i = 0; i < rc; i += 2) {
		if (list[i] == 0xCD && FindFid(0xC9, list[i + 1], list, rc) >= 0) {
			uint8 buf[256];
			int rc = SC_ReadFile(0xC900 | list[i + 1], 0, buf, sizeof(buf));
			if (rc > 0 && FindLabel(label, buf, rc)) {
				*pTemplateFid = 0xCD00 | list[i + 1];
				break;
			}
		}
	}
	if (*pTemplateFid == 0) {
		log_err("template '%s' not found", label);
		return ERR_TEMPLATE;
	}
	return 0;
}

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ************************** Template  Functions ********************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/

typedef struct {
	uint8 Version;
	uint8 HeaderLength;
	uint16 HashLen;
	uint16 CertIdOff; /* unique cert id, 32 uint8 length */
	uint16 SignedAttributesOff;
	uint16 SignedAttributesLen;
	uint16 SigningTimeOff;
	uint16 MessageDigestOff;
	uint16 SignatureOff;
	uint16 SignatureSize;
	uint16 CMSLen;
/* up to here from file */
	uint16 KeyFid;
	uint16 TemplateFid;
	uint8 *pCms;
	char Label[1]; /* space for the 0 terminator, need calloc(1, sizeof(Template_t) + strlen(label)) */
} Template_t;

static Template_t *This; /* current template (singleton) */

#define TEMPLATE_VERSION (0)
#define TEMPLATE_HEADER_LENGTH (20)

static int LoadTemplate(const char *label)
{
	uint8 *pCms;
	int rc, end, off, labelLen;
	if (label == 0)
		return ERR_INVALID;
	labelLen = strlen(label);
	This = (Template_t*)calloc(1, sizeof(Template_t) + labelLen);
	if (This == 0)
		return ERR_MEMORY;
	memcpy(This->Label, label, labelLen + 1); /* include 0 terminator */
	rc = GetFids(label, &This->KeyFid, &This->TemplateFid);
	if (rc < 0)
		goto error;
	/* read template header */
	rc = SC_ReadFile(This->TemplateFid, 0, (uint8*)This, TEMPLATE_HEADER_LENGTH);
	if (rc < 0)
		goto error;
	if (rc != TEMPLATE_HEADER_LENGTH) {
		log_err("template '%s' invalid header length", label);
		rc = ERR_TEMPLATE;
		goto error;
	}
	if (This->Version != TEMPLATE_VERSION || This->HeaderLength != TEMPLATE_HEADER_LENGTH) {
		rc = ERR_VERSION;
		goto error;
	}
#ifdef LITTLE_ENDIAN
#define swap16(field) This->field = This->field >> 8 | This->field << 8;
	swap16(HashLen)
	swap16(CertIdOff)
	swap16(SignedAttributesOff)
	swap16(SignedAttributesLen)
	swap16(SigningTimeOff)
	swap16(MessageDigestOff)
	swap16(SignatureOff)
	swap16(SignatureSize)
	swap16(CMSLen)
#undef swap16
#endif
	/*
		Sanity checks
	*/
	if (This->HashLen != 32) {
		log_err("currently only SHA256 supported");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(0 < This->SignedAttributesOff && This->SignedAttributesOff + This->SignedAttributesLen < This->SignatureOff)) {
		log_err("signed attributes offset/length invalid");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(This->SignedAttributesOff < This->SigningTimeOff
		&& This->SigningTimeOff + 13 <= This->SignedAttributesOff + This->SignedAttributesLen)) {
		log_err("signing time offset invalid");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(This->SignedAttributesOff < This->MessageDigestOff
		&& This->MessageDigestOff + This->HashLen <= This->SignedAttributesOff + This->SignedAttributesLen)) {
		log_err("MessageDigest-Offset missing or invalid");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(0 < This->SignatureOff && This->SignatureOff + This->SignatureSize <= This->CMSLen)) {
		log_err("Signature-Offset missing or invalid");
		rc = ERR_SANITY;
		goto error;
	}
	This->pCms = (uint8*)calloc(1, This->CMSLen);
	if (This->pCms == 0) {
		rc = ERR_MEMORY;
		goto error;
	}
	/* read template body in MAX_OUT_IN bytes portions */
	off = TEMPLATE_HEADER_LENGTH;
	end = off + This->CMSLen;
	pCms = This->pCms;
	while (off < end) {
		int len = end - off;
		if (len > MAX_OUT_IN)
			len = MAX_OUT_IN;
		rc = SC_ReadFile(This->TemplateFid, off, pCms, len);
		if (rc != len) {
			log_err("template '%s' SC_ReadFile(.., %d, .., %d) returned %d", label, off, len, rc);
			rc = ERR_TEMPLATE;
			goto error;
		}
		off += len;
		pCms += len;
	}
	return 0;
error:
	if (This->pCms)
		free(This->pCms);
	free(This);
	This = 0;
	return rc;
}

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ************************** Signature Functions ********************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/

static int PatchSignedAttributes(
	const uint8 *hash, int hashLen,
	uint8 *hashToSign, int hashToSignLen)
{
	time_t now;
	struct tm t;
	char signingTime[16];
	uint8 oldTag;
	sha256_context ctx;
	/* patch signing time */
	time(&now);
	t = *gmtime(&now);
	if (!(2013 - 1900 <= t.tm_year && t.tm_year < 2050 - 1900))
		return ERR_TIME;
	sprintf(signingTime,
			"%02d%02d%02d%02d%02d%02dZ",
			t.tm_year - 100, 1 + t.tm_mon, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec);
	memcpy(This->pCms + This->SigningTimeOff, signingTime, 13);
	/* patch MessageDigest */
	memcpy(This->pCms + This->MessageDigestOff, hash, hashLen);
	/* calculate hash of signed attributes */
	oldTag = This->pCms[This->SignedAttributesOff]; /* save old tag */
	This->pCms[This->SignedAttributesOff] = 0x31; /* change from CONT [0] to SET tag */
	/* todo additional support of at least SHA1 */
	sha256_starts(&ctx);
	sha256_update(&ctx, This->pCms + This->SignedAttributesOff, This->SignedAttributesLen);
	sha256_finish(&ctx, hashToSign);
	This->pCms[This->SignedAttributesOff] = oldTag; /* restore CONT [0] */
	return 0;
}

static int PatchRSATemplate(const uint8 *hash, int hashLen)
{
	/*
	const ASN1 headers to build the asn1 enclosed hash:

		SEQUENCE
			SEQUENCE
				OID of hash
				NULL
			OCTETSTRING hash
	*/
	static const uint8 encSHA256[] =
		"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
#if 0
	static const uint8 encSHA1[] =
		"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
	static const uint8 encSHA384[] =
		"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30";
	static const uint8 encSHA512[] =
		"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40";
#endif
	int ix, encLen;
	const uint8 *enc;
	uint8 *sig;
	int rc;
	uint8 hashToSign[32];
	rc = PatchSignedAttributes(hash, hashLen, hashToSign, sizeof(hashToSign));
	if (rc < 0)
		return rc;
	switch (hashLen) {
	case 32:          /* SHA-256 */
		enc = encSHA256;
		encLen = sizeof(encSHA256) - 1;
		break;
#if 0
	case 20:          /* SHA1 */
		enc = encSHA1;
		encLen = sizeof(encSHA1) - 1;
		break;
	case 48:          /* SHA-384 */
		enc = encSHA384;
		encLen = sizeof(encSHA384) - 1;
		break;
	case 64:          /* SHA-512 */
		enc = encSHA512;
		encLen = sizeof(encSHA512) - 1;
		break;
#endif
	default:
		return ERR_HASH;
	}
	/*
		Build 0x00, 0x01, 0xff, ... , 0xff, 0x00, asn1-enclosed-hash.
		The total size must match exactly the RSA modulus size (RSA2k: 2048 bits == 256 bytes).
		Use space of p->Signature !!!
	*/
	sig = This->pCms + This->SignatureOff;
	ix = This->SignatureSize;
	memcpy(sig + (ix -= hashLen), hashToSign, hashLen);
	memcpy(sig + (ix -= encLen), enc, encLen);
	sig[ix -= 1] = 0;
	memset(sig + 2, -1, ix - 2);
	sig[1] = 1;
	sig[0] = 0;
	return SC_Sign(0x20, (uint8)This->KeyFid, sig, This->SignatureSize, sig, This->SignatureSize);
}

static int PatchECDSATemplate(const uint8 *hash, int hashLen)
{
	int rc;
	uint8 hashToSign[32];
	rc = PatchSignedAttributes(hash, hashLen, hashToSign, sizeof(hashToSign));
	if (rc < 0)
		return rc;
	rc = SC_Sign(0x70, (uint8)This->KeyFid, hashToSign, hashLen, This->pCms + This->SignatureOff, This->SignatureSize);
	if (rc < 0)
		return rc;
	/*
		The following is returned by the token:
		ASN.1 encoding of ECDSA and DSA signature: total length ... 70, 71 or 72
		SEQUENCE // length: ... 68, 69 or 70
			r INTEGER // length: ... 32 or 33 if MSBit set
			s INTEGER // length: ... 32 or 33 if MSBit set
	*/
	int delta = 72 - rc;
	int l;
	if (delta > 0) { /* patch the length fields of the containing ASN.1 elements */
		This->CMSLen -= delta;
		uint8* p = This->pCms;
		if (p[0] != 0x30 || p[1] != 0x82) // SEQUENCE
			return ERR_TEMPLATE;
		l = p[2] << 8 | p[3];
		l -= delta;
		p[2] = l >> 8; p[3] = l; // adjust length
		p += 4;

		if (p[0] != 0x06) // OID
			return ERR_TEMPLATE;
		p += 2 + p[1]; // skip OID
		if (p[0] != 0xA0 || p[1] != 0x82) // CONT [0]
			return ERR_TEMPLATE;
		l = p[2] << 8 | p[3];
		l -= delta;
		p[2] = l >> 8; p[3] = l; // adjust length
		p += 4;

		if (p[0] != 0x30 || p[1] != 0x82) // SEQUENCE
			return ERR_TEMPLATE;
		l = p[2] << 8 | p[3];
		l -= delta;
		p[2] = l >> 8; p[3] = l; // adjust length
		p += 4;

		if (p[0] != 0x02) // INTERGER version
			return ERR_TEMPLATE;
		p += 2 + p[1]; // skip
		if (p[0] != 0x31) // SET 
			return ERR_TEMPLATE;
		p += 2 + p[1]; // skip
		if (p[0] != 0x30) // SEQUENCE
			return ERR_TEMPLATE;
		p += 2 + p[1]; // skip
		if (p[0] != 0xA0 || p[1] != 0x82) // CONT [0]
			return ERR_TEMPLATE;
		p += 4 + (p[2] << 8 | p[3]); // skip
		if (p[0] != 0x31 || p[1] != 0x81) // SET
			return ERR_TEMPLATE;
		l = p[2];
		l -= delta;
		p[2] = l; // adjust length
		p += 3;

		if (p[0] != 0x30 || p[1] != 0x81) // SEQUENCE
			return ERR_TEMPLATE;
		l = p[2];
		l -= delta;
		p[2] = l; // adjust length

		// OCTET string containing the signature
		// works because the the length is 70, 71 or 72
		This->pCms[This->SignatureOff - 1] -= delta; // adjust length
	}
	return rc;
}

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 *******************************************************************************
 **************************** public Functions *********************************
 *******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/
/*
 *  Signature of specified hash
 *
 *  pin         : smartcard pin
 *  label       : key and template label
 *  hash        : Hash to be signed
 *  hashLen     : Length of hash (20, 32, 48 or 64)
 *  ppCms       : returns the CMS data in *ppCms
 *
 *  Returns : CMS size or error if <= 0
 */
int EXPORT_FUNC sign_hash(
	const char *pin, const char *label,
	const uint8 *hash, int hashLen,
	const uint8 **ppCms)
{
	return sign_hash2(0, pin, label, hash, hashLen, ppCms);
}

int EXPORT_FUNC sign_hash2(
	const char *reader, const char *pin, const char *label,
	const uint8 *hash, int hashLen,
	const uint8 **ppCms)
{
	int rc;
	*ppCms = 0;
	if (This) { /* try to reuse template */
		if (strcmp(This->Label, label)) { /* This->Label != label */
			release_template();
		} else {
			uint8 certId[32];
			rc = SC_ReadFile(This->TemplateFid, TEMPLATE_HEADER_LENGTH + This->CertIdOff, certId, sizeof(certId));
			if (rc != sizeof(certId) || memcmp(certId, This->pCms + This->CertIdOff, sizeof(certId)))
				release_template(); /* do not reuse, release rescources */
		}
	}
	if (This == 0) { // start over
		rc = SC_Open(pin, reader);
		if (rc < 0) {
			log_err("SC_Open returned %d", rc);
			return rc;
		}
		rc = LoadTemplate(label);
		if (rc < 0) {
			log_err("LoadTemplate('%s') returned %d", label, rc);
			SC_Close();
			return rc;
		}
	}
	if (This->SignatureSize == 256) /* RSA */
		rc = PatchRSATemplate(hash, hashLen);
	else if (This->SignatureSize == 72)
		rc = PatchECDSATemplate(hash, hashLen);
	if (rc == 70 || rc == 71 || rc == 72 || rc == 256) {
		*ppCms = This->pCms;
		return This->CMSLen; // OK
	}
	/* error case */
	log_err("Template '%s' invalid signature size %d", label, rc);
	release_template();
	if (rc >= 0) 
		rc = ERR_KEY_SIZE;
	return rc;
}

void EXPORT_FUNC release_template()
{
	if (This == 0)
		return;
	SC_Close();
	free(This->pCms);
	free(This);
	This = 0;
}
