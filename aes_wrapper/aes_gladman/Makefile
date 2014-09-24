CFLAGS = -Wall

OBJS =	aescrypt.o	aeskey.o	aes_modes.o				\
		aestab.o				ccm.o		cmac.o		\
		cwc.o		eax.o		gcm.o		gf128mul.o	\
		gf_convert.o			omac.o		tablegen.o

all: libaesgladman.a

libaesgladman.a: $(OBJS)
	$(AR) r $@ $(OBJS)
	$(AR) s $@

.c.o:
	$(CC) $(CFLAGS) $(OFLAGS) -c $<

clean:
	rm -f *.o libaesgladman.*