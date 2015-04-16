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
 * @file sc-hsm-ultralite-signer.c
 * @author Keith Morgan, Christoph Brunhuber
 */

#ifdef __linux__
#define _FILE_OFFSET_BITS 64 /* define before <stdio.h> etc. */
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <ultralite/log.h>
#include <ultralite/sc-hsm-ultralite.h>
#include "metadata.h"

#ifdef _WIN32
#ifdef DEBUG
#include <crtdbg.h>
#endif
#include "ext-win/dirent.h"
typedef __int64 offset_t;
/* define below after <stdio.h> */
#define snprintf _snprintf
#define fseeko _fseeki64
#define ftello _ftelli64
#define stat __stat64
#elif defined __linux__
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define MAX_PATH PATH_MAX
typedef off_t offset_t;
#if !defined __USE_FILE_OFFSET64
#error "Detected no large file support (LFS). Requires Linux > 2.4.0"
#endif
#else
/*
 * The custom type offset_t is normally a signed 64-bit value for
 * large file support, but on systems which do not support the stdio
 * functions with 64-bit parameters, offset_t may be defined as a signed
 * 32-bit value which will constrain support to files < 2 GB in size.
 */
#error "Must implement dirent API and define offset_t for your OS."
#endif

#ifdef CTAPI
#ifdef _WIN32
#define MUTEX_KEY "Global\\sc-hsm-ultralite-signer-mutex"
void* create_lock(const char* name)
{
	HANDLE hMutex;
	DWORD err;
	hMutex = CreateMutex(0, 0, name);
	err = GetLastError();
	if (hMutex == 0) {				
		log_err("error creating mutex %s: %d", name, err);
		return (void*)-1;
	} else if (err == ERROR_ALREADY_EXISTS) {
		/* we require exclusive creation */
		CloseHandle(hMutex);
		return (void*)-1;
	} else {
		return hMutex;
	}
}
void release_lock(void* hMutex)
{
	CloseHandle((HANDLE)hMutex);
}
#elif defined __linux__
#define MUTEX_KEY "/var/lock/sc-hsm-ultralite-signer.lock"
void* create_lock(const char* key)
{
	int err;
	int fd = open(key, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR); /* Add O_CLOEXEC if using any of the exec*() functions */
	if (fd < 0) {
		int e = errno;
		log_err("error opening/creating lock file %s: %s", key, strerror(e));
		return (void*)-1;
	}
	err = flock(fd, LOCK_EX | LOCK_NB);
	if (err) {
		int e = errno;
		if (e != EWOULDBLOCK) /* EWOULDBLOCK is ok => locked by another proc */
			log_err("error locking lock file %s (fd: %d): %s",
				key, fd, strerror(e));
		err = close(fd);
		if (err) {
			int e = errno;
			log_err("error closing lock file %s (fd: %d): %s", key, fd, strerror(e));
		}
		return (void*)-1;
	}
	return (void*)fd;
}
void release_lock(void* _fd)
{
	int fd = (int)_fd;
	int err = flock(fd, LOCK_UN);
	if (err) {
		int e = errno;
		log_err("error unlocking lock file (fd: %d): %s", fd, strerror(e));
	}
	err = close(fd);
	if (err) {
		int e = errno;
		log_err("error closing lock file (fd: %d): %s", fd, strerror(e));
	}
}
#else
#error "Must implement *_lock funcs for your OS. Dummy implementations OK if non-simultaneous token access guaranteed."
#endif
#endif

/**
 * Sign the file at the specified path using the private
 * key with the specified label on a token with the specified pin
 * and optionally with the beginning hash state saved in the
 * specified metadata_t from the previous signing.
 */
static void sign(const char* path, const char* pin, const char* label,
	metadata_t* md)
{
	int n, err, sig_size;
	sha256_context ctx;
	sha256_context ctx_cpy;
	const unsigned char *pCms = 0;
	unsigned char buf[0x10000], hash[32]; /* 32 => 256-bit sha256 */
	char sig_path[MAX_PATH] = "";
	FILE * fpi = 0, * fpo = 0;

	/* Open the data file for reading */
	fpi = fopen(path, "rb");
	if (!fpi) {
		int e = errno;
		log_err("error opening file '%s' for reading: %s", path, strerror(e));
		goto sign_error;
	}

	/* Get the saved hash context or start a new one */
	if (!md) { /* No metadata */
		/* Start a new hash context */
		sha256_starts(&ctx);
	} else { /* Metadata exists */
		/* Restore the saved hash context */
		int ok;
		/* Get the saved hashed content length (hcl) */
		offset_t hcl = sizeof(hcl) == 4 ? md->cll : (offset_t)md->clh << 32 | md->cll;
		/* Adjust the hcl back to the last block boundary */
		hcl = hcl - hcl % sizeof(ctx.buffer);
		/* Restore the "total" (hcl) field to the hash context */
		ctx.total[0] = (unsigned int)hcl;
		ctx.total[1] = (unsigned int)(hcl >> 32);
		/* Restore the state field to the hash context */
		memcpy(&ctx.state, &md->state, sizeof(ctx.state));
		/* Seek to the position of hcl minus one & verify last byte still exists */
		ok = hcl <= 0 || fseeko(fpi, hcl - 1, SEEK_SET) == 0 && getc(fpi) >= 0;
		if (!ok) {
			if (sizeof(hcl) == 4) /* 32-bit hcl */
				log_err("error seeking in '%s' to pos %d", path, (int)hcl);
			else /* 64-bit hcl */
				log_err("error seeking in '%s' to pos %lld", path, hcl);
			goto sign_error;
		}
	}

	/* Create/Continue a SHA-256 hash of the file */
	for (;;) {
		int n = fread(buf, 1, sizeof(buf), fpi);
		if (n <= 0)
			break;
		sha256_update(&ctx, buf, n);
	}

	/* Check for error during read */
	if (ferror(fpi)) {
		log_err("error reading file '%s'", path);
		goto sign_error;
	}

	/* Close the data file */
	err = fclose(fpi);
	if (err) {
		int e = errno;
		log_err("error closing file '%s': %s", path, strerror(e));
		goto sign_error;
	}
	fpi = 0;

	/* Clone the unfinalized hash context to save in the metadata */
	memcpy(&ctx_cpy, &ctx, sizeof(ctx));

	/* Finalize the hash for the current sig */
	sha256_finish(&ctx, hash);

	/* Sign the hash with the token; creates CMS document & puts ptr in pCMS
	   WARNING: sign_hash is not re-entrant (see sc-hsm-ultralite.c) */
	sig_size = sign_hash(pin, label, hash, sizeof(hash), &pCms);
	if (sig_size <= 0) {
		log_err("sign_hash returned error %d", sig_size);
		goto sign_error;
	}

	/* Open the new sig file for writing */
	n = snprintf(sig_path, sizeof(sig_path), "%s.p7s", path);
	if (n < 0 || n >= sizeof(sig_path)) {
		log_err("error building sig file path '%s.p7s'", path);
		goto sign_error;
	}
	fpo = fopen(sig_path, "wb");
	if (!fpo) {
		int e = errno;
		log_err("error opening sig file '%s' for writing: %s",
			sig_path, strerror(e));
		goto sign_error;
	}

	/* Write the CMS document to the sig file */
	n = fwrite(pCms, 1, sig_size, fpo);
	if (n != sig_size) {
		log_err("error writing to sig file '%s'", sig_path);
		goto sign_error;
	}

	/* Save "total" (hcl) & unfinalized hash state at end of sig file */
	err = write_metadata(fpo, &ctx_cpy);
	if (err) {
		log_err("error writing metadata to sig file '%s'", sig_path);
		goto sign_error;
	}

	/* Close the sig file */
	err = fclose(fpo);
	if (err) {
		log_err("error closing sig file '%s'", sig_path);
		goto sign_error;
	}
	fpo = 0;

	/* Success */
	log_inf("'%s' created", sig_path);
	return;

sign_error:
	/* Close input file stream, if open */
	if (fpi) {
		err = fclose(fpi);
		if (err) {
			int e = errno;
			log_err("error closing file '%s': %s",
				path, strerror(e));
		}
	}
	/* Close output file stream, if open */
	if (fpo) {
		err = fclose(fpo);
		if (err) {
			int e = errno;
			log_err("error closing sig file '%s': %s",
				sig_path, strerror(e));
		}
	}
	return;
}

/**
 * Determine if the file at the specified path needs to be signed.
 * Signing only occurs if the file is new (i.e. not yet signed),
 * OR if the file has been appended since the last signing as
 * determined by reading the hcl ("total") from the metadata stored
 * at the end of the associated signature file and comparing with the
 * current size of the specified file.
 * If a new signature is necessary, the sign function above will be
 * called with the specified pin and label.
 */
void sign_file(const char* path, const char* pin, const char* label)
{
	int n, err;
	struct stat entry_info;
	struct stat sig_info;
	char sig_path[PATH_MAX] = "";

	/* Stat the entry */
	err = stat(path, &entry_info);
	if (err) {
		int e = errno;
		log_err("error accessing file '%s': %s", path, strerror(e));
		return;
	}

	/* Only sign files */
	if (S_ISDIR(entry_info.st_mode))
		return;

	/* Skip empty files */
	if (entry_info.st_size <= 0) {
		log_inf("'%s' empty", path);
		return;
	}

	/* Build associated sig file path (i.e. <path>/<filename>.p7s) */
	n = snprintf(sig_path, sizeof(sig_path), "%s.p7s", path);
	if (n < 0 || n >= sizeof(sig_path)) {
		log_err("error building sig file path '%s.p7s'", path);
		return;
	}

	/* Stat the sig file to see if one exists yet */
	err = stat(sig_path, &sig_info);

	if (!err) { /* Sig file found => figure out if we need to re-create it */
		/* Read the metadata from the sig file */
		metadata_t md;
		err = read_metadata(sig_path, &md);
		if (err) {
			log_err("error reading metadata from sig file '%s'; will be re-created", sig_path);
		} else {
			/* Figure out if we need to re-create the sig file */
			offset_t hcl = sizeof(hcl) == 4 ? md.cll : (offset_t)md.clh << 32 | md.cll;
			if (entry_info.st_size == hcl) {
				/* Unmodified so skip */
				log_inf("'%s' unmodified", path);
				return;
			} else if (entry_info.st_size < hcl) {
				/* Shrunk so re-sign */
				log_wrn("'%s' shrunk", path);
				err = 1; /* force re-sign from beginning of file */
			} else {
				/* Modified so re-sign the file using the hash state saved in the metatdata */
				log_inf("'%s' modified", path);
			}
		}
		/* Create/re-create sig file */
		sign(path, pin, label, err ? 0 : &md);
	} else { /* No sig file found (or err reading it) => create/re-create */
		int e = errno;
		if (e == ENOENT) /* A sig file doesn't yet exist, assume file is new */
			log_inf("'%s' not yet signed", path);
		else /* Error accessing an existing sig file */
			log_err("error accessing sig file '%s': %s; will be re-created", sig_path, strerror(e));
		/* Create/re-create sig file */
		sign(path, pin, label, 0);
	}
}

/**
 * Scan through the specified (directory) path and call sign_file on
 * each file that is not hidden nor a signature (.p7s).
 * The specified pin and label will be used for signing, if necessary.
 */
void sign_files(const char* path, const char* pin, const char* label)
{
	int err;
    DIR* dir;
    struct dirent* entry;
	const char* ext;

    /* Open directory stream */
    dir = opendir(path);
    if (dir == NULL) {
		int e = errno;
		log_err("error opening path '%s': %s", path, strerror(e));
		return;
	}

	/* Loop through each entry in the specified path */
    while ((entry = readdir(dir)) != NULL) {
		int n;
		char entry_path[MAX_PATH];

		/* Skip "./" "../" and hidden files that begin with '.' */
		if (entry->d_name[0] == '.')
			continue;

		/* TODO: Allow recursion on sub-directories? */

		/* Skip ".p7s" files */
		ext = strrchr(entry->d_name, '.');
		if (ext && (strcmp(ext, ".p7s") == 0))
			continue;

		/* Create the full path to the entry */
		n = snprintf(entry_path, sizeof(entry_path),
			"%s/%s", path, entry->d_name);
		if (n < 0 || n >= sizeof(entry_path)) {
			log_err("error building entry path '%s/%s'", path, entry->d_name);
			continue;
		}

		/* Sign the file */
		sign_file(entry_path, pin, label);
    }

	/* Close the directory stream */
    err = closedir(dir);
	if (err) {
		int e = errno;
		log_err("error closing path '%s': %s", path, strerror(e));
	}

}

int main(int argc, char** argv)
{
	int i;
	const char * pin, * label;
#ifdef CTAPI
	void* mutex;
#endif

	/* Check args */
	if (argc < 4) {
		fprintf(stderr, "Usage: pin label path...\n");
		fprintf(stderr, "Sign the specified file(s) and/or all files within the specified directory(ies).\n");
		return 1;
	}
	pin = argv[1];
	label = argv[2];

	/* Disable buffering on stdout/stderr to prevent mixing the order of
	   messages to stdout/stderr when redirected to the same log file */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Log the args */
	log_inf("pin=****; label='%s'", label);

#ifdef CTAPI
	/* Create a mutex/sem/lock for controlling access to token.
	   CTAPI implementations must NOT allow simultaneous access to token. */
	mutex = create_lock(MUTEX_KEY);
	if ((int)mutex < 0) {
		log_wrn(
			"couldn't create mutex; another inst. of '%s' is likely running", argv[0]);
		return -1;
	}
#endif

	/* For each path arg, sign either the specified file
	   or all the files in the specified directory */
	for (i = 3; i < argc; i++) {
		int err;
		struct stat info;
		char* path = argv[i];

		/* Trim trailing slashes from path (required for Windows stat) */
		int j = strlen(path);
		while (--j >= 0 && (path[j] == '/' || path[j] == '\\'))
			path[j] = 0;

		/* Log the path */
		log_inf("path='%s'", path);

		/* Verify the specified path exists */
		err = stat(path, &info);
		if (err) {
			int e = errno;
			log_err("error accessing path '%s': %s", path, strerror(e));
			continue;
		}

		if (S_ISDIR(info.st_mode)) /* DIRECTORY */
			sign_files(path, pin, label); /* Sign all files in the specified directory */
		else /* FILE */
			sign_file(path, pin, label);  /* Sign the specified file */
	}

	/* Clean up */
	release_template();

#ifdef CTAPI
	/* Release mutex/sem/lock here. */
	release_lock(mutex);
#endif

#if defined(_WIN32) && defined(DEBUG)
	_CrtDumpMemoryLeaks();
#endif
	return 0;
}
