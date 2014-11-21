include ../Makefile.config

ifeq ($(MAKECMDGOALS), clean)
	DIRS = ctccid
else ifndef CTAPI
	MSG = $(info *** Building sc-hsm-embedded with  PCSC interface! ***)
else
	DIRS = ctccid
	MSG = $(info *** Building sc-hsm-embedded with CTAPI interface! ***)
endif

$(info *****************************************************)
$(MSG)
$(info *****************************************************)

DIRS += pkcs11 tests ultralite ultralite-tests ultralite-tool ultralite-signer

all:
	@for dir in $(DIRS); do $(MAKE) -C $$dir all; done

clean:
	@for dir in $(DIRS); do $(MAKE) -C $$dir clean; done
