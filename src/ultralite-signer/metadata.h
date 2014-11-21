/**
 * SmartCard-HSM Ultra-Light Library Signer Application
 *
 * Copyright (c) 2013. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the BSD 3-Clause License. You should have
 * received a copy of the BSD 3-Clause License along with this program.
 * If not, see <http://opensource.org/licenses/>
 *
 * @file metadata.h
 * @author Keith Morgan, Christoph Brunhuber
 */

#ifndef _METADATA_H_
#define _METADATA_H_

#include <stdio.h>
#include <ultralite/log.h>
#include <ultralite/sc-hsm-ultralite.h>

#define METADATA_MAGIC "EatZeroRedAnts!" /* metadata_t constant id value */
#define METADATA_VERSION 104 /* metadata_t version number */

#define swap32(val) ( val >> 24 | (0x00FF0000 & val) >> 8 | (0x0000FF00 & val) << 8 | (0x000000FF & val) << 24 )

/**
 * Structure for saving the latest hashed content length (total) and
 * hash context state (state) to disk as metadata. Saving the hashed
 * content length allows quick determination if the associated data
 * file has been modified since the last signing while saving the
 * hash context state allows re-signing a file quickly by only
 * hashing new data which has been appended to the file.
 */
typedef struct
{
/*  Beg private fields */
	union {
		struct {
			unsigned char thumb[32]; /* struct integrity hash */
			unsigned int  state[ 8]; /* sha256_context::state */
		};
		struct _private {
			unsigned char thumb[32]; /* struct integrity hash */
			unsigned int  state[ 8]; /* sha256_context::state */
		} u;
		/* Force to 16-byte boundary so no gaps in req fields */
		char __private[(sizeof(struct _private) + 15) / 16 * 16];
	};
/*  End private fields */
	char magic[16];   /* Offset: EOF - 32; metadata_t const id value */
	unsigned int clh; /* Offset: EOF - 16; hi word of content length */
	unsigned int cll; /* Offset: EOF - 12; lo word of content length */
	unsigned int len; /* Offset: EOF -  8; metadata_t len w/ private */
	unsigned int ver; /* Offset: EOF -  4; metadata_t version number */
} metadata_t;

/**
 * Compute the thumbprint (SHA-256) of a metadata_t struct
 */
static void get_thumb(metadata_t* md, unsigned char thumb[32]) /* 32 => 256-bit sha-256 */
{
	sha256_context ctx;
	sha256_starts(&ctx);
	sha256_update(&ctx, (unsigned char*)&md->state, (unsigned int)((char*)(&md->ver + 1) - (char*)md->state));
	sha256_finish(&ctx, thumb);
}

/**
 * Write a metadata_t to the specified file stream.
 */
int write_metadata(FILE* fp, sha256_context* hash_ctx)
{
	int n;
	metadata_t md;

	/* Initialize the metadata_t struct with the specified values */
	memset(&md, 0, sizeof(md));
	memcpy(md.state, hash_ctx->state, sizeof(md.state));
	memcpy(md.magic, METADATA_MAGIC,  sizeof(md.magic));
#ifdef LITTLE_ENDIAN
	md.clh = swap32(hash_ctx->total[1]);
	md.cll = swap32(hash_ctx->total[0]);
	md.len = swap32(sizeof(md));
	md.ver = swap32(METADATA_VERSION);
#else
	md.clh = hash_ctx->total[1];
	md.cll = hash_ctx->total[0];
	md.len = sizeof(md);
	md.ver = METADATA_VERSION;
#endif

	/* Create & store a thumbprint of the metadata_t struct */
	get_thumb(&md, md.thumb);

	/* Write the metadata_t struct to the file stream */
	n = fwrite(&md, sizeof(metadata_t), 1, fp);
	if (n != 1) {
		int e = errno;
		log_err("error writing metadata_t: %s", strerror(e));
		return e;
	}

	return 0;
}

/**
 * Read a metadata_t from the end of the specified path
 */
int read_metadata(const char* path, metadata_t* md)
{
	int n, err, rv = -1;
	FILE* fp = 0;
	unsigned char thumb[32]; /* 32 => 256-bit sha256 */

	/* Open the specified path for reading */
	fp = fopen(path, "rb");
	if (!fp) {
		rv = errno;
		log_err("error opening '%s' for reading: %s", path, strerror(rv));
		goto read_metadata_cleanup;
	}

	/* Seek to the end of the file, minus the size of one metadata_t struct */
	err = fseek(fp, -(int)sizeof(*md), SEEK_END);
	if (err) {
		rv = errno;
		log_err("error seeking to offset %d (from end) in '%s': %s", -(int)sizeof(*md), path, strerror(rv));
		goto read_metadata_cleanup;
	}

	/* Read one metadata_t struct from the file stream */
	n = fread(md, sizeof(*md), 1, fp);
	if (n != 1) {
		rv = errno;
		log_err("error reading metadata_t from '%s': %s", path, strerror(rv));
		goto read_metadata_cleanup;
	}

	/* Verify the thumbprint */
	get_thumb(md, thumb);
	if (memcmp(thumb, md->thumb, sizeof(thumb))) {
		log_err("error reading metadata_t from '%s': thumbprint mismatch", path);
		goto read_metadata_cleanup;
	}

	/* Convert back to little endian, if necessary */
#ifdef LITTLE_ENDIAN
	md->clh = swap32(md->clh);
	md->cll = swap32(md->cll);
	md->len = swap32(md->len);
	md->ver = swap32(md->ver);
#endif

	/* Verify the version */
	if (md->ver != METADATA_VERSION) {
		log_err("error reading metadata_t from '%s': version exp: %d act: %d",
			path, METADATA_VERSION, md->ver);
		goto read_metadata_cleanup;
	}

	/* Verify the length */
	if (md->len != sizeof(*md)) {
		log_err("error reading metadata_t from '%s': length exp: %d act: %d",
			path, sizeof(*md), md->len);
		goto read_metadata_cleanup;
	}

	/* Verify the "magic" value */
	if (strcmp(md->magic, METADATA_MAGIC)) {
		log_err("error reading metadata_t from '%s': magic exp: '%s' act: '%s'",
			path, METADATA_MAGIC, md->magic);
		goto read_metadata_cleanup;
	}

	/* Success */
	rv = 0;

read_metadata_cleanup:
	/* Close file stream, if open */
	if (fp) {
		err = fclose(fp);
		if (err) {
			rv = errno;
			log_err("error closing file '%s': %s", path, strerror(rv));
		}
	}

	return rv;
}

#endif /* _METADATA_H_ */
