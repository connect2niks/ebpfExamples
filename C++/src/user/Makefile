INCLUDE_DIR = ../../include/user
PROG_NAME = fentry

CXX = g++
CXXFLAGS = -std=c++20 -I$(INCLUDE_DIR) -pthread
LDFLAGS = -lbpf -pthread

USER_SRCS = event.cpp main.cpp
USER_OBJS = $(USER_SRCS:.cpp=.o)

ifeq ($(CONFIG_RENAME),y)
CXXFLAGS += -DCONFIG_RENAME
endif

all: USER_BUILD

%.o: %.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS)

USER_BUILD: $(USER_OBJS)
	$(CXX) $(USER_OBJS) -o ../../$(PROG_NAME) $(LDFLAGS)

clean:
	rm -f ../../$(PROG_NAME)
	rm -f *.o