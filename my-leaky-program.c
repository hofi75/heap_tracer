
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int counter = 0;

#define ADDRESS_TABLE_SIZE	1024

void	*addresses[ADDRESS_TABLE_SIZE];

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
    size = rand() % 1024;
	// printf( "allocate %ld bytes...\n", size);
	p = malloc( size);
	memset( p, 0x55, size);
	if ( rand() % 2)
	{
		p = realloc( p, size * 3);
		memset( p, 0xaa, size * 3);
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

int main( void)
{
	memset( addresses, 0, sizeof( addresses));
    for( int i = 0; i < 10; i++)
    {
    	RECURSIVE_FUNCTION_BODY
    }
}
