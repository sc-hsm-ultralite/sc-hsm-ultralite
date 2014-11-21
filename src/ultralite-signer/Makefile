include ../../Makefile.config

CFLAGS += -I..
LDFLAGS = -lpthread

ifndef CTAPI # PCSC
	LDFLAGS += $(PCSC_LDFLAGS)
else
	ADD_LIB = ../ctccid/libctccid.a
	LDFLAGS += $(USB_LDFLAGS)
endif

all: sc-hsm-ultralite-signer

OBJ = sc-hsm-ultralite-signer.o log.o

sc-hsm-ultralite-signer: $(OBJ)
	$(CC) -o sc-hsm-ultralite-signer $(OBJ) ../ultralite/libsc-hsm-ultralite.a $(ADD_LIB) $(LDFLAGS)

clean:
	rm -f *.o sc-hsm-ultralite-signer
 