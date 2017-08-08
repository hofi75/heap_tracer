
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int counter = 0;

int bar( void)
{
    long size;
    char *p;

    /*
    size = 246;
    p = malloc( size);
    memset( p-4, 'H', size);
    free( p);

    p = malloc( size);
    memset( p+4, 'H', size);
    free( p);

    return 0;
    */ 
    counter ++;
    if ( counter < 5) bar();

    for ( int i = 0; i < 1; i++)
    {
	size = rand() % 1024;
	// printf( "allocate %ld bytes...\n", size);
	p = malloc( size);
	memset( p, 0x55, size);
	p = realloc( p, size * 3);
	memset( p, 0xaa, size * 3);
	if ( i % 2) free( p);
	// if ( i % 3) { free(p);free(p);free(p);free(p);}
    }

    // free( p);

    return 0;
}

int foo()
{
    bar();
}

int main( void)
{
    foo();
}
