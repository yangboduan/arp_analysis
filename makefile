CPP      = g++
CC       = gcc
CFLAGS   = -g -Wall
OBJ      = arp_ananysis.o
LINKOBJ  = arp_ananysis.o
BIN      = arp_ananysis
RM       = rm -rf
LIB	 = -lpcap
$(BIN): $(OBJ)
	$(CPP) $(LINKOBJ) -o $(BIN)   $(LIB) $(CFLAGS) 

	
clean: 
	${RM} $(OBJ) $(BIN)

cleanobj:
	${RM} *.o

