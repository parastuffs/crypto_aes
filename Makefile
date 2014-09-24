CC = gcc
CFLAGS = -Wall
AES_WRAP_DIR = aes_wrapper/
OPT_LIB = -ldl
OBJ = aes_main.o generic_tools.o $(AES_WRAP_DIR)aes_all_modes.o
EXE_NAME = aes_main
# DEBUG=-g3

all : $(EXE_NAME)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

########
# EXE
########
$(EXE_NAME) : $(OBJ)
	$(CC) $(DEBUG) $(CFLAGS) -o $@ $(OBJ) -L$(AES_WRAP_DIR)polarssl-1.3.8/library/ -lpolarssl -L$(AES_WRAP_DIR)openssl-1.0.1i/ -lcrypto -L$(AES_WRAP_DIR)aes_gladman/ -laesgladman $(OPT_LIB)

##############
# Object list
##############
aes_main.o : aes_main.c
	$(CC) $(CFLAGS) -c $< -o $@ -Iaes_wrapper/

generic_tools.o : generic_tools.c
	$(CC) $(CFLAGS) -c $< -o $@

$(AES_WRAP_DIR)aes_all_modes.o : $(AES_WRAP_DIR)aes_all_modes.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(AES_WRAP_DIR)polarssl-1.3.8/include/ -I$(AES_WRAP_DIR)aes_gladman/ -I$(AES_WRAP_DIR)openssl-1.0.1i/include/


clean:
	rm -f $(OBJ)
	rm -f $(EXE_NAME)
