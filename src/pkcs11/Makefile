include ../../Makefile.config

CFLAGS += -I..
LDFLAGS = -shared -lpthread

ifndef CTAPI # PCSC
	CFLAGS += $(PCSC_CFLAGS)
	LDFLAGS += $(PCSC_LDFLAGS)
else # CTAPI
	CFLAGS += $(USB_CFLAGS)
	LDFLAGS += $(USB_LDFLAGS)
	ADD_LIB = ../ctccid/libctccid.a
endif

all: libsc-hsm-pkcs11.so

OBJ = dataobject.o debug.o object.o p11generic.o p11mechanisms.o p11objects.o \
	p11session.o p11slots.o session.o slot.o slot-ctapi.o slot-pcsc.o slotpool.o \
	strbpcpy.o token.o token-sc-hsm.o certificateobject.o privatekeyobject.o asn1.o \
	pkcs15.o ../common/mutex.o

libsc-hsm-pkcs11.so: $(OBJ)
	$(CC) -o libsc-hsm-pkcs11.so $(OBJ) $(ADD_LIB) $(LDFLAGS)

clean:
	rm -f *.o *.so $(OBJ)
