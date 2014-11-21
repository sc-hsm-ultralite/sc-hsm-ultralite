include ../../Makefile.config

CFLAGS += -I..

ifndef CTAPI # PCSC
	CFLAGS += $(PCSC_CFLAGS)
else # CTAPI
	CFLAGS += $(USB_CFLAGS)
endif

all: libsc-hsm-ultralite.a

OBJ = sc-hsm-ultralite.o sha256.o utils.o log.o

libsc-hsm-ultralite.a: $(OBJ)
	$(AR) crs libsc-hsm-ultralite.a $(OBJ)

clean:
	rm -f *.o *.a
