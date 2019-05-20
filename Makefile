# demo.out : main.c send.c get_interface.c
# 	@gcc main.c send.c get_interface.c -o demo.out -lpthread
# clean :
# 	rm demo.out

SRC := #
SRC += main.c 
SRC += send.c
SRC += recv.c
SRC += link_list.c
# SRC += firewall_op.c
SRC += get_interface.c



#OBJ := $(subst .c,.o,$(SRC))
OBJ = $(SRC:%.c=%.o)

# export PKG_CONFIG_PATH=/opt/gtkdfb/lib/pkgconfig
# PREFIX = /opt/gtkdfb
# LDFLAGS=-L${PREFIX}/lib -Wl,-rpath,${PREFIX}/lib 
# CFLAGS=-I${PREFIX}/include/gtk-2.0/ 

CC = gcc
# FLAG = -Wall $(LDFLAGS) $(CFLAGS) `pkg-config --cflags --libs gtk+-2.0 gthread-2.0`
FLAG = -Wall 
# OPTION = -lpthread -ldl 
OPTION = -lpthread 
EXEC_NAME = demo
EXEC_PATH = .

.PHONY:clean demo

demo:$(OBJ)
	@echo make ...
	$(CC) $^ -o $(EXEC_PATH)/$(EXEC_NAME) $(FLAG) $(OPTION)
	@echo make over
	@echo Execute target is sudo $(EXEC_PATH)/$(EXEC_NAME)
$(OBJ):%.o:%.c
	$(CC) -c -o $@ $< $(FLAG)
clean:
	@echo clean ...
	rm $(EXEC_PATH)/$(EXEC_NAME) *.o -rf
	@echo clean over