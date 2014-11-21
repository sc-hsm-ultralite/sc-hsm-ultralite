This document covers the theory of the sc-hsm-ultralite library.

Although sc-hsm-embedded is a light-weight library for crypto
token access, it does not alleviate the burden of creating PKCS#7
ASN.1 encoded signature files (either attached or detached). The
sc-hsm-ultralite library was created with the purpose of removing
the need for a heavy cryptography library (e.g. openssl, cryptlib
etc.) just to create ASN.1 documents. The sc-hsm-ultralite library
accomplishes this goal by using so-called template files. A
template file is nothing more than an actual PKCS#7 detached
signature file that has been created with external tools and loaded
to the crypto token.  The sc-hsm-ultralite library reads the
template file off the token into memory.  When a new signature is
needed, it can simply ask the token for the raw signature (e.g. RSA, 
ECDSA, etc.) and then patch the template in memory with the new
signature.  The details are slightly more sophisticated (e.g. the
signing time must also be patched and included in the final hash).
Detailed information can be found in the source code itself (see
sc-hsm-ultralite.c).

The library was designed such that only sc-hsm-ultralite.h needs
to be included.  For an example of the simplest usage of the
library, see ultralite-tests/c.

The library logging simply prints messages to stdout (info) and
stderr (error).  If desired, the logging can be easily replaced
by changing the implementation of log.c.  For an example, see
ultralite-signer.
