
all: heap_tracer.so my-leaky-program heap_tracer2.so
clean:
#	rm heap_tracer
	rm -f heap_tracer.so
	rm -f heap_tracer2.so
	rm -f my-leaky-program

#heap_tracer: heap_tracer.c
#gcc -shared -fPIC memory_debug.c -o memory_debug.so
#	gcc -rdynamic -Wno-deprecated-declarations -g -std=c99 heap_tracer.c -o heap_tracer

my-leaky-program: my-leaky-program.c
	gcc -rdynamic my-leaky-program.c -o my-leaky-program
#	gcc my-leaky-program.c -o my-leaky-program

heap_tracer.so: heap_tracer.c
	gcc -rdynamic -Wno-deprecated-declarations -g3 -std=c99 -fPIC -shared heap_tracer.c -o heap_tracer.so

heap_tracer2.so: heap_tracer2.c
	gcc -rdynamic -Wno-deprecated-declarations -g3 -std=c99 -fPIC -shared heap_tracer2.c -o heap_tracer2.so
