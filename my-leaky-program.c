
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <search.h>

int counter = 0;

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


int allocator( void)
{
    long 	size;
    int		i;
    void	*p;
/*
    switch( rand() % 3)
    {
    case 0:
    	for( i = 0; i < ADDRESS_TABLE_SIZE; i++)
    		if ( addresses[i] == NULL)
    			addresses[i] = malloc( rand() % 1024);
    	break;
    case 1:
    {
    	int	iteration = rand() % 1024, k;
    	for( k = 0; k < iteration; k++)
    	{

    	}
    }
*/
    size = 16 + rand() % 256;
    if ( rand() % 2)
    	p = malloc( size);
    else
    	p = memalign( 32, size);

	memset( p, 0x55, size);
	strcpy( p, "MALLOC/MEMALIGN");

	if ( rand() % 2)
	{
		p = realloc( p, size * 3);
		memset( p, 0xaa, size * 3);
		strcpy( p, "REALLOC");
	}

	if ( rand() % 2) free( p);

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
/*	void *troot = NULL;
	int		a = 10, b = 20, c = 15, d = 3, f = 9;

	printf( "tfind(f)\n");
	tfind( &f, &troot, compare);
	printf( "tsearch(a)\n");
	tsearch( &a, &troot, compare);
	printf( "tsearch(b)\n");
	tsearch( &b, &troot, compare);
	printf( "tsearch(c)\n");
	tsearch( &c, &troot, compare);
	printf( "tsearch(d)\n");
	tsearch( &d, &troot, compare);
	printf( "tdelete(b)\n");
	tdelete( &b, &troot, compare);
	printf( "tfind(f)\n");
	tfind( &f, &troot, compare);
	malloc( 1000);
	malloc( 1000);
*/
	free( ( void *) 0x1000);
	free( ( void *) 0x2000);
	free( ( void *) 0x3000);
	free( ( void *) 0x4000);
    for( int i = 0; i < 1000; i++)
    {
    	RECURSIVE_FUNCTION_BODY
    }
}
