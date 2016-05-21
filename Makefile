ifeq ($(pc), 1)
PREFIX = 
else
PREFIX = arm-none-linux-gnueabi-
endif

CPP = 	$(PREFIX)g++
CC = 	$(PREFIX)gcc
ECHO = 	echo
GOAL = 	openssl_test.x

CFLAGS += -I.
CFLAGS += -O2 -W -Wall -Wno-unused-function -Wno-unused-variable -g

LDFLAGS += -lssl -lcrypto -lcurl

GEN_OBJS += main.o
GEN_OBJS += encrypt_rsa.o
GEN_OBJS += base64.o
GEN_OBJS += http.o
GEN_OBJS += encrypt_des.o

all: $(GOAL) 

#-------------------------------------------------------------------
# --- Common Message, please don't remove. 
#-------------------------------------------------------------------
MSG_SPLIT_LINE = 
MSG_COMPILING = @$(ECHO) "	Compiling <$<>"
MSG_GOAL_OK = @$(ECHO) "*** " $@ "is built successfully."

$(GOAL): $(GEN_OBJS)
	@$(CC) $(CFLAGS) $(GEN_OBJS) -o $@ $(LDFLAGS)
	@$(MSG_GOAL_OK)

clean:
	@rm -f $(GEN_OBJS)
	@rm -f *.d
	@rm -f codepage/*.d
	@rm -f $(GOAL)
	@$(ECHO) clean done


#-------------------------------------------------------------------
# Implicit rules
#-------------------------------------------------------------------

.c.o:
	$(MSG_SPLIT_LINE)
	$(MSG_COMPILING)
	@$(CC) $(CFLAGS) -MM -MT $@ -o $*.d $<
	@$(CC) -c $(CFLAGS) -o $*.o $<



