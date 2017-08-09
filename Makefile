
all: heap_tracer.so my-leaky-program
clean:
#	rm heap_tracer
	rm -f heap_tracer.so
	rm -f my-leaky-program

heap_tracer.so: heap_tracer.c
	gcc -shared -fPIC -rdynamic -Wno-deprecated-declarations -g -std=c99 heap_tracer.c -o heap_tracer.so

my-leaky-program: my-leaky-program.c
	gcc -rdynamic my-leaky-program.c -g -o my-leaky-program
