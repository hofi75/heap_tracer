
#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <search.h>
#include <unistd.h>

int counter = 0;
#define ALLOC_MAX_SIZE 2048

void bar0();
void bar1();
void bar2();
void bar3();
void foo();

#define RECURSIVE_FUNCTION_BODY \
	switch( rand() % 6) \
	{ \
		case 0: bar0(); break; \
		case 1: bar1(); break; \
		case 2: bar2(); break; \
		case 4: bar3(); break; \
		case 5: foo (); break; \
		default: allocator(); break; \
	}

#define MAX_ADDR	(64*1024)
void	*addr[MAX_ADDR];
int		addrs = 0, maxaddrs = 0;

int allocator( void)
{
	int		i, x = 4, size;

	/* give more chance for free */
	if ( addrs > 10) x = 6;

    switch( rand() % x)
    {
	case 0: /* malloc */
	case 1:
		if ( addrs >= MAX_ADDR) break;
		size = rand() % ALLOC_MAX_SIZE;
		addr[addrs] = malloc( size);
		memset( addr[addrs], 'A' + rand() % 26, size);
		addrs++;
    	break;
    case 2: /* realloc */
		if ( addrs >= MAX_ADDR) break;
		if ( addrs == 0) break;
		i = rand() % addrs;
		size = rand() % ALLOC_MAX_SIZE;
		addr[i] = realloc( addr[i], size);
		memset( addr[i], 'A' + rand() % 26, size);
		break;
    default:
		if ( addrs == 0) break;
		i = rand() % addrs;
		free( addr[i]);
		addrs--;
		addr[i] = addr[addrs];
		addr[addrs] = NULL;
	}
	
	if ( addrs > maxaddrs) maxaddrs = addrs;
	// printf( "addrs = %d\n", addrs);

    return 0;
}

void bar0( void)
{
	RECURSIVE_FUNCTION_BODY
}
void bar1( void)
{
	RECURSIVE_FUNCTION_BODY
}
void bar2( void)
{
	RECURSIVE_FUNCTION_BODY
}
void bar3( void)
{
	RECURSIVE_FUNCTION_BODY
}

void foo()
{
	RECURSIVE_FUNCTION_BODY
}

static int compare( const void *p1, const void *p2)
{
	int *a = ( int *) p1, *b = ( int *) p2;

	printf( "compare(%d,%d)\n", *a, *b);

	if ( *a > *b) return 1;
	if ( *a < *b) return -1;

	return 0;
}

int main( void)
{
	int i;

    for( i = 0; i < 10000; i++)
    {
    	RECURSIVE_FUNCTION_BODY
		// printf( "%d,", i);
		// usleep( 1000);
	}

	printf( "\n");
	printf( "number of unallocated entries = %d(max=%d)\n", addrs, maxaddrs);
	for( i = 0; i < addrs; i++)
		printf( "%p, ", addr[i]);
	printf( "\n");

	return 0;
}
