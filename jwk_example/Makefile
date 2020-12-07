NAME= jwk_test
SRCS = main.cc \
	   json.cc \
	   jwk.cc

INCS = -I/usr/local/ssl/lib
LIBS = -lcrypto -lpthread -ldl -lrt

build:
	g++ -std=c++17 $(INCS) -o $(NAME) $(SRCS) $(LIBS)

clean:
	rm $(NAME)

