include ../../../Makefile.config

CFLAGS += -I../..
LDFLAGS = -lpthread

ifndef CTAPI # PCSC
	LDFLAGS += $(PCSC_LDFLAGS)
else
	ADD_LIB = ../../ctccid/libctccid.a
	LDFLAGS += $(USB_LDFLAGS)
endif

all: sc-hsm-ultralite-test

OBJ = sc-hsm-ultralite-test.o

sc-hsm-ultralite-test: $(OBJ)
	$(CC) -o sc-hsm-ultralite-test $(OBJ) ../../ultralite/libsc-hsm-ultralite.a $(ADD_LIB) $(LDFLAGS)

clean:
	rm -f *.o sc-hsm-ultralite-test
 