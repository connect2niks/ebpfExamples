

INCLUDE_DIR = ../../include/user
PROG_NAME = fentry


all : USER_BUILD 


USER_BUILD:
	g++ main.cpp -o ../../$(PROG_NAME) -lbpf -std=c++17 -I$(INCLUDE_DIR)

clean:
	rm ../../$(PROG_NAME)