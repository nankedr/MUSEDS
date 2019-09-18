all:test_main test_dynamic test_2014 
LIBS = -lssl -lcrypto -lpbc -lgmp
OBJS0 = main.o
OBJS1 = dynamic.o
OBJS2 = main2014.o
INCLUDES = /usr/local/include/pbc
test_main:main_M.c hash.h
	gcc -g -W -Wall -I $(INCLUDES) $(LIBS) -c  $< -o $(OBJS0)
	g++ -o $@ $(OBJS0) $(LIBS)
test_dynamic:main_dynamic.c hash.h
	gcc -g -W -Wall -I $(INCLUDES) $(LIBS) -c  $< -o $(OBJS1)
	g++ -o $@ $(OBJS1) $(LIBS)
test_2014:main2014.c hash.h
	gcc -g -W -Wall -I $(INCLUDES) $(LIBS) -c  $< -o $(OBJS2)
	g++ -o $@ $(OBJS2) $(LIBS)
clean:
	rm -f *.o test_dynamic test_2014 test_main

