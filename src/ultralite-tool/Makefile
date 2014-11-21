include ../../Makefile.config

CFLAGS += -I..
LDFLAGS = -lpthread

ifndef CTAPI # PCSC
	LDFLAGS += $(PCSC_LDFLAGS)
else
	ADD_LIB = ../ctccid/libctccid.a
	LDFLAGS += $(USB_LDFLAGS)
endif

all: sc-hsm-ultralite-tool

sc-hsm-ultralite-tool: sc-hsm-ultralite-tool.o
	$(CC) -o sc-hsm-ultralite-tool $< ../ultralite/libsc-hsm-ultralite.a $(ADD_LIB) $(LDFLAGS)

clean:
	rm -f *.o sc-hsm-ultralite-tool
