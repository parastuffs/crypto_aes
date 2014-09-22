CC = gcc
CFLAGS = -Wall
OBJ = aes_main.o aes_all_modes.o generic_tools.o
EXE_NAME = aes_main
# DEBUG=-g3

all : $(EXE_NAME)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

########
# EXE
########
$(EXE_NAME) : $(OBJ)
	$(CC) $(DEBUG) $(CFLAGS) -o $@ $(OBJ) -Iopenssl-1.0.1i/include -Lopenssl-1.0.1i/ -lcrypto -Laes_gladman/ -laesgladman -Lpolarssl-1.3.8/library/ -lpolarssl -ldl

##############
# Object list
##############
aes_main.o : aes_main.c
	$(CC) $(CFLAGS) -c $< -o $@

aes_all_modes.o : aes_all_modes.c
	$(CC) $(CFLAGS) -c $< -o $@ -Iopenssl-1.0.1i/include/ -lcrypto -Laes_gladman/ -laesgladman -Lpolarssl-1.3.8/library/ -Ipolarssl-1.3.8/include/ -lpolarssl

generic_tools.o : generic_tools.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)
	rm -f $(EXE_NAME)
