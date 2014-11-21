include ../../Makefile.config

CFLAGS += -I..
LDFLAGS = -ldl -lpthread

ifndef CTAPI # PCSC
	LDFLAGS += $(PCSC_LDFLAGS)
	ALL = sc-hsm-pkcs11-test
else # CTAPI
	LDFLAGS += $(USB_LDFLAGS)
	ALL = ctccid-test sc-hsm-pkcs11-test
endif

all: $(ALL)

ctccid-test: ctccid-test.o
	$(CC) -o ctccid-test $< ../ctccid/libctccid.a $(LDFLAGS)

sc-hsm-pkcs11-test: sc-hsm-pkcs11-test.o
	$(CC) -o sc-hsm-pkcs11-test $< $(LDFLAGS)

clean:
	rm -f *.o ctccid-test sc-hsm-pkcs11-test
