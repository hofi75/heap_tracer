
all: heap_tracer.so my-leaky-program heap_tester
clean:
#	rm heap_tracer
	rm -f heap_tracer.so heap_tracer.o
	rm -f heap_tester
	rm -f my-leaky-program

heap_tracer.o: heap_tracer.c
	g++ -fPIC -c -g -Wno-deprecated-declarations -fpermissive -o heap_tracer.o heap_tracer.c

heap_tracer.so: heap_tracer.o
	g++ -fPIC -shared -Wl,--no-undefined -rdynamic -g -o heap_tracer.so heap_tracer.o

my-leaky-program: my-leaky-program.c
	gcc -rdynamic my-leaky-program.c -g -std=c99 -o my-leaky-program

heap_tester: heap_tester.c
	gcc -rdynamic heap_tester.c -g -ldl -std=c99 -o heap_tester

#test_getgrgid: test_getgrgid.c
#	gcc -rdynamic test_getgrgid.c -g -o test_getgrgid
