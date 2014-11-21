include ../../Makefile.config

ifndef CTAPI
	ifneq ($(MAKECMDGOALS), clean)
		MSG = $(error *** This package is not needed for the PCSC interface! ***)
	endif
endif

$(MSG)

CFLAGS += -I..

all: libctccid.a

OBJ = ctapi.o ctbcs.o usb_device.o ccidT1.o ccidAPDU.o ccid_usb.o ctccid_debug.o ../common/mutex.o

libctccid.a: $(OBJ)
	$(AR) crs libctccid.a $(OBJ)

clean:
	rm -f *.a *.o $(OBJ)

