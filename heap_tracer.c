#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

#define _POSIX_SOURCE
// #define __USE_LIBUNWIND

#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdarg.h>
/* Prototypes for __malloc_hook, __free_hook */
#include <malloc.h>
#include <execinfo.h>
#include <string.h>
#include <ucontext.h>
#include <search.h>
#include <fcntl.h>

 // #define __USE_GNU
#include <dlfcn.h>

#include <time.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <pthread.h>
#include <time.h>

#ifdef __USE_LIBUNWIND
#   define UNW_LOCAL_ONLY
#   include <libunwind.h>
#   include <cxxabi.h>
#endif

#define flag_set( _flag, _mask) \
   _flag |= _mask;
#define flag_reset( _flag, _mask) \
   _flag &= ~(_mask);
#define flag_test( _flag, _mask) \
   ( _flag & ( _mask))

#define SIZE_CHECK_AREA				32
#define SIZE_BACKTRACE_STRING		4096

typedef struct __allocate_entry {
	char 				eyec[4];
	unsigned long long 	id;
	void 				*addr;			// points to user memory
	// void 				*real_addr;		// points to libc allocated memory
	size_t 				size;
	pid_t				pid;
	int					intervalID;
	char				timestamp[48];
  	struct timespec 	tp;
#ifdef __USE_LIBUNWIND
// 	unw_cursor_t 		bt_cursor[64];
#endif
	char 				checkstring[SIZE_CHECK_AREA];
	char 				backtrace[SIZE_BACKTRACE_STRING];
	char				*cs_right;
	char				cs_left[SIZE_CHECK_AREA];
} allocate_entry_t;

typedef struct __heap_tracer_context {
	FILE 				*heap_report;
	int 				unused;
	int					entries;
	int					allocated;
	int 				max_entries;
	int 				max_size;
	int					nof_invalid_free;
	// int 				size;
	unsigned long long 	id;
	pthread_mutex_t 	lock;
	pid_t				start_pid;
	int 				flag;
#define	FLAG_ACTIVE					0x0001
#define	FLAG_TRACE_MODULE			0x0002
#define	FLAG_TRACE_HEAP_CALLS		0x0004
#define	FLAG_BACKTRACE				0x0008
#define	FLAG_CHECK_BOUNDARIES		0x0010
#define	FLAG_LOCKING				0x0020
#define	FLAG_BACKTRACE_FD			0x0040
#define FLAG_TRACE_ALL				0x0080
	int 				flag_active;
	int 				flag_trace_calls;
	int 				flag_backtrace;
	int					bt_pipes[2];
	int					intervalID;
	size_t				dump_limit;
	size_t				dump_interval;
	size_t				ignore_interval;
	time_t				dump_next;
	time_t				ignore_until;
	int					ignore_from;
} heap_tracer_context_t;

#define is_active			flag_test( htc->flag, FLAG_ACTIVE)
#define is_trace_calls		flag_test( htc->flag, FLAG_TRACE_HEAP_CALLS)
#define is_trace_module		flag_test( htc->flag, FLAG_TRACE_MODULE)
#define is_trace_all		flag_test( htc->flag, FLAG_TRACE_ALL)
#define is_backtrace		flag_test( htc->flag, FLAG_BACKTRACE)
#define is_check_boundaries	flag_test( htc->flag, FLAG_CHECK_BOUNDARIES)
#define is_locking			flag_test( htc->flag, FLAG_LOCKING)
#define is_backtrace_fd		flag_test( htc->flag, FLAG_BACKTRACE_FD)

static void prepare(void) __attribute__((constructor));
static void unload(void) __attribute__((destructor));

void generate_backtrace_string(char *result);

int set_checkstring	(allocate_entry_t *ae);
int check_boundaries(allocate_entry_t *ae);

int trc(const char *, ...);
int	trc_delimiter_line();
void __dump(const char *title, char *addr, size_t len);

extern const char *__progname;
static	void *troot = NULL;

/* Prototypes for our hooks.  */
static void *ht_malloc(size_t, const void *);
static void *ht_memalign(size_t, size_t, const void *);
static void *ht_realloc(void *, size_t, const void *);
static void  ht_free(void *, const void *);

/* Variables to save original hooks. */
static void *(*old_malloc_hook)(size_t, const void *);
static void *(*old_memalign_hook)(size_t, size_t, const void *);
static void *(*old_realloc_hook)(void *, size_t, const void *);
static void (*old_free_hook)(void *, const void *);

int memcheck(void *x);

void hooks_backup(void);
void hooks_restore(void);
void hooks_setmine(void);

static heap_tracer_context_t shtc;
static heap_tracer_context_t *htc = &shtc;

#define SIZE_TABLE 		( sizeof ( allocate_entry_t) * htc->size)

#define HT_ENV 		"HEAP_TRACER"
#define LOCK

#define HT_LOCK \
	if ( is_locking) pthread_mutex_lock( &htc->lock);
#define HT_UNLOCK \
	if ( is_locking) pthread_mutex_unlock( &htc->lock);

static void *(*real_malloc) (size_t size) = 0;
static void (*real_free) (void *ptr) = 0;
static void *(*real_realloc) (void *ptr, size_t size) = 0;
static void *(*real_calloc) (size_t nmemb, size_t size) = 0;

void ht_close			( void);
void ht_open			( void);
int  ht_interval_shift	( int all);
int  ht_dump_entries	( size_t intervalID);

static void prepare(void) {
	ht_open();
}

void ht_open(void) 
{
	char *htenv, *p, temp[256], report_path[256];
	struct sigaction sa;

	memset( htc, 0, sizeof( heap_tracer_context_t));
	strcpy( report_path, "");

	// check if our program name is defined in HEAP_TRACER
	htenv = getenv( HT_ENV);
	if ( !htenv || strlen( htenv) == 0)
	{
		printf( 
			"heap tracer preload library\n"
			"usage: \n"
			"	export HEAP_TRACER='[options]'; LD_PRELOAD=./heap_tracer.so [userprogram]\n\n"
			"options (space delimited):\n"
			"	vebose1\n"
			"		traces all malloc/realloc/memalign/free calls\n"
			"	verbose2\n"
			"		verbose1 + heap tracer debug output\n"
			"	verbose3\n"
			"		trace all, max verbosity\n"
			"	bracktrace\n"
			"		collects backtrace data with backtrace_symbols() function\n"
			"	backtrace_fd\n"
			"		collects backtrace data with backtrace_symbols_fd() function\n"
			"	check_boundaries\n"
			"		checks memory over/underwrites, allocated areas are surrounded by eyecatcher\n"
			"	locking\n"
			"		locks heap tracer functions, usefull for multithread applications\n"
			"	dump_limit=B\n"
			"		limit for dumping size, default 64kb\n"
			"	ignore_until=S\n"
			"		ignore memory leaks where allocation was made in first S seconcs, default=0\n"
			"	ignore_interval=N\n"
			"		ignore dumping first N interval, default=0 --> all\n"
			"	dump_interval=S\n"
			"		dumps allocations within specified interval, default=0\n");
		return;
	}
	
	char *d;

	printf( "size of allocate_entry_t = %ld\n", sizeof( allocate_entry_t));

	printf("heap tracer environment settings '%s'\n", htenv);
	if ((p = strstr(htenv, "progname=")) != NULL) {
		sprintf(temp, "program name=%s", __progname);
		if ((p = strstr(htenv, temp)) == NULL)
			return;
	}

	memset(report_path, 0, sizeof(report_path));
	if ((p = strstr(htenv, "report_path=")) != NULL)
		for (d = report_path, p += 12; *p != '\0' && *p != ' '; p++, d++)
			*d = *p;

	if ((p = strstr(htenv, "verbose1")) != NULL)
		flag_set(htc->flag, FLAG_TRACE_HEAP_CALLS);

	if ((p = strstr(htenv, "verbose2")) != NULL)
		flag_set(htc->flag, FLAG_TRACE_HEAP_CALLS |
							FLAG_TRACE_MODULE);

	if ((p = strstr(htenv, "verbose3")) != NULL)
		flag_set(htc->flag, FLAG_TRACE_HEAP_CALLS |
							FLAG_TRACE_MODULE |
							FLAG_TRACE_ALL);

	if ((p = strstr(htenv, "backtrace")) != NULL)
		flag_set(htc->flag, FLAG_BACKTRACE);

	if ((p = strstr(htenv, "backtrace_fd")) != NULL)
		flag_set(htc->flag, FLAG_BACKTRACE | FLAG_BACKTRACE_FD);

	if ((p = strstr(htenv, "check_boundaries")) != NULL)
		flag_set(htc->flag, FLAG_CHECK_BOUNDARIES);

	if ((p = strstr(htenv, "locking")) != NULL)
		flag_set(htc->flag, FLAG_LOCKING);

	htc->dump_limit = 64*1024;
	if ((p = strstr(htenv, "dump_limit=")) != NULL)
		htc->dump_limit = atoi( p + 11);

	if ((p = strstr(htenv, "ignore_until=")) != NULL)
		htc->ignore_until = atoi( p + 13);

	htc->dump_interval = 0;
	if ((p = strstr(htenv, "dump_interval=")) != NULL)
		htc->dump_interval = atoi( p + 14);

	htc->ignore_interval = 0;
	if ((p = strstr(htenv, "ignore_interval=")) != NULL)
		htc->ignore_interval = atoi( p + 16);

	sprintf( temp, "%sheap_report_%s_%d.txt", report_path, __progname, getpid());
	if ( ( htc->heap_report = fopen( temp, "w+t")) == NULL) {
		printf( "unable to create heap report (%s)\n", temp);
		exit( 16);
	}

	printf( "heap trace file is '%s'\n", temp);

	trc( "heap trace file '%s' opened for\n", temp);
	trc( "\texecutable            = '%s'\n", __progname);
	trc( "\tenvironment           = '%s'\n", htenv);
	trc( "\tbacktracing           = %s\n", ( is_backtrace) ? "yes" : "no");
	trc( "\tbacktracing mode      = %s\n", ( is_backtrace_fd) ? "file descriptor" : "normal");
	trc( "\ttrace calls           = %s\n", ( is_trace_calls) ? "yes" : "no");
	trc( "\ttrace module          = %s\n", ( is_trace_module) ? "yes" : "no");
	trc( "\ttrace all             = %s\n", ( is_trace_all) ? "yes" : "no");
	trc( "\tbounday check         = %s\n", ( is_check_boundaries) ? "yes" : "no");
	trc( "\tlock                  = %s\n", ( is_locking) ? "yes" : "no");
	trc( "\tdump limit            = %d bytes\n", htc->dump_limit);
	trc( "\tdump interval         = %d seconds\n", htc->dump_interval);
	trc( "\tignore interval       = %d\n", htc->ignore_interval);
	trc( "\tignore until          = %d seconds\n", htc->ignore_until);
	trc( "\n");

	flag_set( htc->flag, FLAG_ACTIVE);

	if ( is_locking)
		pthread_mutex_init(&htc->lock, NULL);

	if ( is_backtrace_fd)
	{
		pipe( htc->bt_pipes);
		trc( "\tbacktrace pipes     = %d/%d\n", htc->bt_pipes[0], htc->bt_pipes[1]);
		int retval = fcntl( htc->bt_pipes[0], F_SETFL, fcntl(htc->bt_pipes[0], F_GETFL) | O_NONBLOCK);
		// trc( "fcntl retcode = %d\n", retval);
	}

	htc->ignore_until 	+= time( NULL);
	htc->dump_next		= time( NULL) + htc->dump_interval;
	htc->start_pid		= getpid();

	hooks_backup();
	hooks_setmine();
}

static int ae_compare_id( const void *node1, const void *node2) {
	allocate_entry_t *ae1 = (allocate_entry_t *) node1;
	allocate_entry_t *ae2 = (allocate_entry_t *) node2;

	if (ae1->id == ae2->id) return 0;
	if (ae1->id < ae2->id)	return -1;

	return 1;
}

static int ae_compare_address( const void *node1, const void *node2)
{
	allocate_entry_t *ae1 = (allocate_entry_t *) node1;
	allocate_entry_t *ae2 = (allocate_entry_t *) node2;
	int rslt = 0;

	if ( is_trace_all)
	{
		trc( "compare -->\n");
		trc( "compare(%p,%p)\n", ae1, ae2);
		trc( "\taddr(%p <--> %p)\n", ae1->addr, ae2->addr);
	}

	if ( ae1->addr < ae2->addr)	rslt = -1;
	if ( ae1->addr > ae2->addr)	rslt = 1;

	if ( is_trace_all)
		trc( "compare result = %d\n", rslt);

	return rslt;
}

static void unload(void) 
{
	ht_close();
}

void ht_close( void)
{
	int i;
	size_t sum;
	allocate_entry_t *ae;

	if (!is_active) return;

	hooks_restore();

	trc_delimiter_line();
	trc( "-=>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FINAL SUMMARY REPORT <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<=-\n");
	trc_delimiter_line();
	trc( "number of unallocated entries : %d\n", htc->entries);
	trc( "size   of unallocated entries : %ld kB\n",
			(long) (htc->allocated / (1024)));

	trc( "max number of entries         : %d\n", htc->max_entries);
	trc( "max memory usage              : %ld kB\n", (long) (htc->max_size / (1024)));
	trc( "number of invalid free calls  : %d\n", htc->nof_invalid_free);
	trc_delimiter_line();

	/* dump all enties */
	ht_dump_entries( -1);

	tdestroy( troot, &free);

	fclose( htc->heap_report);
	if ( is_backtrace_fd)
	{
		close( htc->bt_pipes[0]);
		close( htc->bt_pipes[1]);
	}
}

#define BT_ARRAY_SIZE 100

void * array[BT_ARRAY_SIZE];

#ifdef __USE_LIBUNWIND
void generate_backtrace_string( char *result)
{
	unw_cursor_t cursor;
	unw_context_t context;

	*result = '\0';
	if (!is_backtrace) return;

  	unw_getcontext( &context);
  	unw_init_local( &cursor, &context);

  	int n=0, i=0, l = SIZE_BACKTRACE_STRING, x;
  	char *p;
   
	p = result;
	while ( unw_step( &cursor) ) 
	// while ( unw_step( &cursor) ) 
	{
		unw_word_t ip, sp, off;

		// unw_get_reg( &cursor, UNW_REG_IP, &ip);
		// unw_get_reg( &cursor, UNW_REG_SP, &sp);

		char symbol[256] = {"<unknown>"};
		char *name = symbol;

		if ( !unw_get_proc_name( &cursor, symbol, sizeof(symbol), &off) ) {
			int status;
			if ( (name = abi::__cxa_demangle(symbol, NULL, NULL, &status)) == 0 ) name = symbol;
		}

    	x = snprintf( p, l, "\t\t#%.2d " " %s + 0x%" PRIxPTR "\n",
        			++n, name, static_cast<uintptr_t>(off));
 /*
    x = snprintf( p, l, "\t\t#%-2d 0x%016" PRIxPTR " sp=0x%016" PRIxPTR " %s + 0x%" PRIxPTR "\n",
        ++n,
        static_cast<uintptr_t>(ip),
        static_cast<uintptr_t>(sp),
        name,
        static_cast<uintptr_t>(off)); */

	// x = snprintf( p, l, "\t\t(%2d) - %s\n", i, name);
		p += x;
		l -= x;
		i++;
    	if ( name != symbol) free( name);
  	}
    
	snprintf( p, l, "\t\tstring size = %ld\n", strlen( result));  
}
#else
void generate_backtrace_string( char *result) {
	char **messages;
	char *p;
	int size, i, l, x;

	*result = '\0';
	if (!is_backtrace) return;

	if ( is_trace_module) trc("%s -->\n", __FUNCTION__);

	size = backtrace( array, BT_ARRAY_SIZE);
	/* if ( is_trace_module) trc("\tbacktrace size = %d\n", size); */

	if ( is_backtrace_fd)
	{
		backtrace_symbols_fd( array, size, htc->bt_pipes[1]);
		i = read( htc->bt_pipes[0], result, SIZE_BACKTRACE_STRING-1);
		result[i] = '\0';

		/* read remaining from pipe */
		/* char  temp[256];
		for( i = 0;; i++)
			if ( read( htc->bt_pipes[0], temp, sizeof( temp)) == 0) break; */
	} else
	{
		messages = backtrace_symbols( array, size);

		for ( l = SIZE_BACKTRACE_STRING, p = result, i = 2; i < size && messages[i] != NULL; ++i) 
		{
			x = snprintf( p, l - 1, "\t\t(%2d) - %s\n", i, messages[i]);
			p += x;
			l -= x;
			if (l < 400) break;
		}
		free( messages);
	}

	if ( is_trace_module)
		trc("%s <-- \n%s\n", __FUNCTION__, result);
}
#endif

void hooks_backup(void) {
	old_malloc_hook = __malloc_hook;
	old_memalign_hook = __memalign_hook;
	old_realloc_hook = __realloc_hook;
	old_free_hook = __free_hook;
}

void hooks_restore(void) {
	__malloc_hook = old_malloc_hook;
	__memalign_hook = old_memalign_hook;
	__realloc_hook = old_realloc_hook;
	__free_hook = old_free_hook;
}

void hooks_setmine(void) {
	__malloc_hook = ht_malloc;
	__memalign_hook = ht_memalign;
	__realloc_hook = ht_realloc;
	__free_hook = ht_free;
}

allocate_entry_t * add_ae( allocate_entry_t *ae, size_t size) {

  	int 			result;
  	struct timespec tp;
	struct tm 		ltime;
	clockid_t 		clk_id;

	if ( is_trace_module) trc("%s(ae=%p, address=%p, %ld,troot=%p) -->\n", __FUNCTION__, ae, ( ae + 1), size, troot);

	memcpy( ae->eyec, "%%AE", 4);
	ae->addr = ( void *) ( ae + 1);
	ae->size = size;
	ae->id = htc->id++;
	ae->pid = getpid();
	htc->allocated += size;
	ae->intervalID = htc->intervalID;
	clk_id = CLOCK_REALTIME_COARSE;
  	result = clock_gettime( clk_id, &ae->tp);

	/* save in binary three */
	ae = *( allocate_entry_t **) tsearch( ( void *) ae, &troot, &ae_compare_address);

	/* update statistics */
	htc->entries++;
	if ( htc->entries > htc->max_entries) 	htc->max_entries = htc->entries;
	if ( htc->allocated > htc->max_size) 	htc->max_size = htc->allocated;

	if ( is_trace_module) trc( "%s <-- (ae=%p, troot=%p)\n", __FUNCTION__, ae, troot);

	return ae;
}

allocate_entry_t * remove_ae( void *addr)
{
	int 			 	i, found = 0;
	allocate_entry_t	ssearch_ae;
	allocate_entry_t 	*search_ae = &ssearch_ae, *ae;

	if ( is_trace_module) trc("%s(%p,troot=%p) -->\n", __FUNCTION__, addr, troot);

	if ( addr == NULL) return ( allocate_entry_t *) NULL;
		
	/* search by address */
	memset( search_ae, 0, sizeof( allocate_entry_t));
	search_ae->addr = addr;

	if ( is_trace_module) trc( "tfind(search_ae=%p,addr=%p)\n", search_ae, search_ae->addr);
	void *x = tfind( ( void *) search_ae, &troot, &ae_compare_address);
	if ( !x)
	{
		trc("? (tfind - NOT found) - / %p  ==> \n%s\n", addr, backtrace);
		return ( allocate_entry_t *) NULL;
	}

	ae = *( allocate_entry_t **) x;
	if ( is_trace_module) trc( "tdelete(search_ae=%p,addr=%p)\n", ae, ae->addr);
	if ( tdelete( ( void *) ae, &troot, &ae_compare_address) == NULL)
	{
		trc( "tdelete error!!!!");
		exit( 16);
	}

	/* update statistics */
	htc->entries--;
	htc->allocated -= ae->size;
	if ( htc->allocated > htc->max_size) htc->max_size = htc->allocated;

	if ( is_trace_module) trc( "%s <-- (ae=%p,troot=%p)\n", __FUNCTION__, ae, troot);

	return ae;
}

static void *ht_malloc( size_t size, const void *caller)
{
	char *addr;
	allocate_entry_t *ae;
	size_t alloc_size = size + sizeof( allocate_entry_t);

	HT_LOCK;
	hooks_restore();

	if ( is_trace_module) trc("%s( %ld) -->\n", __FUNCTION__, size);

	ae = ( allocate_entry_t *) malloc( alloc_size);
	add_ae( ae, size);
	generate_backtrace_string( ae->backtrace);

	if ( is_trace_calls) trc("+ (MALLOC)  %10ld / %8p  ==> \n%s\n", size, ae->addr, ae->backtrace);

	if ( is_trace_module) trc("%s() <-- %p\n", __FUNCTION__, addr);

	hooks_setmine();
	HT_UNLOCK;

	return ae->addr;
}

static void *ht_memalign( size_t alignment, size_t size, const void *caller) {
	allocate_entry_t *ae;
	size_t alloc_size = size + sizeof( allocate_entry_t);

	HT_LOCK;
	hooks_restore();

	if ( is_trace_module) trc("%s( %d, %ld) -->\n", __FUNCTION__, alignment, size);

	ae = ( allocate_entry_t *) memalign( alignment, alloc_size);
	add_ae( ae, size);
	generate_backtrace_string( ae->backtrace);
	// set_checkstring( ae);

	if ( is_trace_calls) trc("+ (MEMALIGN) %10ld / %8p  ==> \n%s\n", size, ae->addr, ae->backtrace);

	if ( is_trace_module) trc("%s( %d, %ld) <-- %p\n", __FUNCTION__, alignment, size, ae->addr);

	hooks_setmine();
	HT_UNLOCK;

	return ae->addr;
}

static void *ht_realloc( void *ptr, size_t size, const void *caller)
{
	char 				*addr;
	allocate_entry_t 	*ae = NULL;
	size_t 				alloc_size = size + sizeof( allocate_entry_t);
	char 				bts[SIZE_BACKTRACE_STRING];

	HT_LOCK;
	hooks_restore();

	if ( is_trace_module) trc("%s( %p, %ld) -->\n", __FUNCTION__, ptr, size);

	if ( ptr)
	{
		ae = ( allocate_entry_t *) remove_ae( ptr);
		// if ( ae == NULL) return 0;
		// generate_backtrace_string( bts);
	}

	ae = ( allocate_entry_t *) realloc( ( void *) ae, alloc_size);
	add_ae( ae, size);
	generate_backtrace_string( ae->backtrace);

	if ( is_trace_calls) {
		trc("- (REALLOC)          - / %8p  ==> \n%s\n", ptr, ae->backtrace);
		trc("+ (REALLOC) %10ld / %8p  ==> \n%s\n", size, ae->addr, ae->backtrace);
	}

	// set_checkstring( ae);
	if ( is_trace_module) trc("%s( %p, %ld) <-- %p\n", __FUNCTION__, ptr, size, ae->addr);

	hooks_setmine();
	HT_UNLOCK;

	return ae->addr;
}

static void ht_free(void *ptr, const void *caller)
{
	char 				bts[SIZE_BACKTRACE_STRING];
	allocate_entry_t	*ae;

	HT_LOCK;
	hooks_restore();

	if ( is_trace_calls) trc("%s(%p) -->\n", __FUNCTION__, ptr);

	ae = remove_ae( ptr);
	if ( ae == NULL)
	{
		/*
		generate_backtrace_string( bts);
		if ( strstr( bts, "ZUDATZT_Now2 + 0x1c") == NULL)
		{
			trc_delimiter_line();
			trc( "***** Invalid free for address(%p), entry not found by heap_tracer ***** \n", ptr);
			trc( "BackTrace: \n%s\n", bts);
			htc->nof_invalid_free ++;
		}
		*/

		if ( is_trace_module) trc("%s <--\n", __FUNCTION__);
		hooks_setmine();
		HT_UNLOCK;
		return;
	}

	free( ( void *) ae);

	if ( is_trace_calls) trc("%s(%p,allocate_entry=%p) <--\n", __FUNCTION__, ptr, ae);

	hooks_setmine();
	HT_UNLOCK;
}

void __dump(const char *title, char *addr, size_t len) {
	int i, m;
	char s1[256], s2[256], s3[256], s4[2];
	unsigned char *p = (unsigned char *) addr;

	trc("DUMPING(%s): %p(%ld)\n", title, addr, len);

	if ( htc->dump_limit && len > htc->dump_limit) len = htc->dump_limit;

	if (memcheck(addr)) {
		trc("\t\tpoints to illegal memory\n");
		return;
	}

	sprintf(s1, "%p - %.8X: ", p, 0);
	strcpy(s2, "\0");
	s4[1] = '\0';
	for (i = 0; i < len; i++) {
		sprintf(s3, "%.2X ", *p);
		strcat(s1, s3);

		switch (i % 32) {
		case 3:
		case 7:
		case 11:
		case 19:
		case 23:
		case 27:
			strcat(s1, " ");
			break;
		case 15:
			strcat(s1, " -  ");
			break;
		}
		s4[0] = (isprint(*p)) ? *p : '.';
		strcat(s2, s4);
		p++;

		if (i % 32 == 31) {
			trc("%s  >%s<\n", s1, s2);
			sprintf(s1, "%p - %.8X: ", p, i + 1);
			strcpy(s2, "\0");
		}
	}

	if (strlen(s2) != 0)
		trc("%-128s  >%s<\n", s1, s2);

	trc("\n");
	fflush(htc->heap_report);
}

size_t unallocated_count, unallocated_size, dump_intervalID;

void ht_dump_entries_action( 
	const void 	*node,
	VISIT		type,
	int			level)
{
	allocate_entry_t 	*ae = *( allocate_entry_t **) node;

	/* nothing to do? */
	if ( type != leaf && type != preorder) return;
	if ( !( dump_intervalID == -1 || ae->intervalID == dump_intervalID)) return;

	/* never dump warmup entries */
	if ( ae->intervalID == 0) return;

	struct tm ltime;
	localtime_r( &ae->tp.tv_sec, &ltime);
	sprintf( ae->timestamp, "%.4d%.2d%.2d/%.2d%.2d%.2d.%ld", 
		ltime.tm_year + 1900, ltime.tm_mon + 1, ltime.tm_mday,
		ltime.tm_hour, ltime.tm_min, ltime.tm_sec, 
		ae->tp.tv_nsec);
	// ae->timestamp[0] = '\0';
	trc_delimiter_line();
	trc("[intervalID=%d] AREA (ID=%lld, @=%p, size=%ld, timestamp=%s) is still not unallocated (pid=%d)\n",
			ae->intervalID, ae->id, ae->addr, ae->size, ae->timestamp, ae->pid);
	trc("   backtrace = \n%s\n", ae->backtrace);
	unallocated_count ++;
	unallocated_size += ae->size;
	__dump("AREA", ( char *) ae->addr, ae->size);
	
}

/* used to sort by ID */
typedef struct __ae_sort {
	unsigned long long	ID;
	allocate_entry_t	*ae;
} ae_sort_t;

ae_sort_t			*ae_sort_table = NULL;
int					ae_sort_size = 0;

void ht_collect_action( 
	const void 	*node,
	VISIT		type,
	int			level)
{
	allocate_entry_t 	*ae = *( allocate_entry_t **) node;

	/* nothing to do? */
	if ( type != leaf && type != preorder) return;
	if ( !( dump_intervalID == -1 || ae->intervalID == dump_intervalID)) return;

	/* never dump warmup entries */
	if ( ae->intervalID == 0) return;

	ae_sort_table[ae_sort_size].ID = ae->id;
	ae_sort_table[ae_sort_size].ae = ae;

	unallocated_count 	++;
	unallocated_size  	+= ae->size;
	
	ae_sort_size++;
}


static int ae_sort_by_ID( const void *p1, const void *p2)
{
	ae_sort_t	*aes1 = ( ae_sort_t *) p1, *aes2 = ( ae_sort_t *) p2;

	if ( aes1->ID < aes2->ID) return -1;
	if ( aes1->ID > aes2->ID) return 1;

	return 0;
}

int ht_dump_entries( size_t intervalID)
{
	allocate_entry_t	*ae;
	unallocated_count 	= 0;
	unallocated_size  	= 0;
	dump_intervalID 	= intervalID;

	ae_sort_table = ( ae_sort_t *) malloc( sizeof( ae_sort_t) * htc->entries + 1000);
	ae_sort_size  = 0;
	twalk( troot, &ht_collect_action);
	qsort( ae_sort_table, ae_sort_size, sizeof( ae_sort_t), &ae_sort_by_ID);

	/*
	trc( "INTERVAL SUMMARY REPORT [current intervalID=%d] (%s)\n", htc->intervalID, ( intervalID == -1) ? "ALL" : "");
	trc( "Unallocated areas ( count, size=%ld KB) = %d\n", unallocated_count, unallocated_size / 1024);
	*/

	trc_delimiter_line();
	for( int i = 0; i < ae_sort_size; i++)
	{
		ae = ae_sort_table[i].ae;


		if ( strstr( ae->backtrace, "libuccache.so") != NULL) continue;

		struct tm ltime;
		localtime_r( &ae->tp.tv_sec, &ltime);
		sprintf( ae->timestamp, "%.4d%.2d%.2d/%.2d%.2d%.2d.%ld", 
			ltime.tm_year + 1900, ltime.tm_mon + 1, ltime.tm_mday,
			ltime.tm_hour, ltime.tm_min, ltime.tm_sec, 
			ae->tp.tv_nsec);
		trc_delimiter_line();
		trc("[intervalID=%d] AREA (ID=%lld, @=%p, size=%ld, timestamp=%s) is still not unallocated (pid=%d)\n",
				ae->intervalID, ae->id, ae->addr, ae->size, ae->timestamp, ae->pid);
		trc("   backtrace = \n%s\n", ae->backtrace);
		unallocated_count ++;
		unallocated_size += ae->size;
		__dump("AREA", ( char *) ae->addr, ae->size);
	}
	free( ae_sort_table);
	ae_sort_size = 0;

	//twalk( troot, &ht_collect_entries_action);
	trc_delimiter_line();
	trc( "INTERVAL SUMMARY REPORT [intervalID=%d] (%s)\n", htc->intervalID, ( intervalID == -1) ? "ALL" : "");
	trc( "Unallocated areas: count=%ld, size=%ld KB\n", unallocated_count, unallocated_size / 1024);
	trc_delimiter_line();


	return 0;
}


/*
	switches to new interval, dumps all entres created in prev interval
*/
int ht_interval_shift( int all)
{
	time_t now = time( NULL);

	// if ( htc->dump_interval == 0) return 0;
	// if ( htc->dump_next >= now) return 0;

	/* 	
		check, if we were called from any timezone/localtime function,
		it locks localtime_r() call, causing deadlock.
		handle interval dump in next calls 
	*/
	/*
	htc->dump_next += htc->dump_interval;
	if ( htc->intervalID < htc->ignore_interval)
	{
		trc( "Interval %d is ignored, due to start parameter\n", htc->intervalID);
		htc->intervalID ++;
		return 0;
	}
	*/
	char backtrace_string[8192];
	generate_backtrace_string( backtrace_string);

	trc( "dumping interval-ID=%d\n", htc->intervalID);
	trc( "current backtrace string = \n%s\n", backtrace_string);
	// if ( strstr( backtrace_string, "heap_tracer_trigger") == NULL) return 0;
    
	/*
	struct tm ltime;
	char	it1[32], it2[32];
	time_t	interval_start = htc->dump_next - htc->dump_interval;
	localtime_r( &interval_start, &ltime);
	sprintf( it1, "%.4d%.2d%.2d/%.2d%.2d%.2d", 
		ltime.tm_year + 1900, ltime.tm_mon + 1, ltime.tm_mday,
		ltime.tm_hour, ltime.tm_min, ltime.tm_sec);
	localtime_r( &htc->dump_next, &ltime);
	sprintf( it2, "%.4d%.2d%.2d/%.2d%.2d%.2d", 
		ltime.tm_year + 1900, ltime.tm_mon + 1, ltime.tm_mday,
		ltime.tm_hour, ltime.tm_min, ltime.tm_sec);
		*/


	/* dump */
	if ( all)	
		ht_dump_entries( -1);
	else
		ht_dump_entries( htc->intervalID);

	/* new allocs identified by new intervalID */
	htc->intervalID ++;
	flag_set( htc->flag, FLAG_BACKTRACE); // activate backtrace

	return 0;
}


static jmp_buf jump;

void segv(int sig) {
	longjmp( jump, 1);
}

int memcheck(void *x) {
	volatile char c;
	int illegal = 0;

	signal(SIGSEGV, segv);

	if (!setjmp(jump))
		c = *(char *) (x);
	else
		illegal = 1;

	signal(SIGSEGV, SIG_DFL);

	return (illegal);
}

int set_checkstring(allocate_entry_t *ae) {
	char temp[256];

	if ( !is_check_boundaries) return 0;

	if ( ae == NULL) return 0;

	sprintf(temp, "#*#*%p<***>%.10ld#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*",
				ae->addr, ae->size);
	memcpy( ae->checkstring, temp, SIZE_CHECK_AREA);
	memcpy( ae->cs_left,  ae->checkstring, SIZE_CHECK_AREA);
	memcpy( ae->cs_right, ae->checkstring, SIZE_CHECK_AREA);

	return 0;
}

int check_boundaries(allocate_entry_t *ae) {
	int corrupted = 0;

	if (!is_check_boundaries) return 0;

	if (ae == NULL)	return 0;

	if ( memcmp(ae->cs_left, ae->checkstring, SIZE_CHECK_AREA) != 0) {
		trc("memory buffer HEADER check string corrupted...\n");
		corrupted = 1;
	}

	if ( memcmp( ae->cs_right, ae->checkstring, SIZE_CHECK_AREA) != 0) {
		trc("memory buffer TRAILER check string corrupted...\n");
		corrupted = 1;
	}

	if ( corrupted) {
		trc( "\taddr      = %p\n", ae->addr);
		trc( "\tsize      = %ld\n", ae->size);
		trc( "\nbacktrace = %s\n", ae->backtrace);
		__dump( "CHECKSTRING", ae->checkstring, SIZE_CHECK_AREA);
		__dump( "LEFT", ( char *) ae->cs_left, SIZE_CHECK_AREA);
		__dump( "RIGHT", ( char *) ae->cs_right, SIZE_CHECK_AREA);
		// __dump( "FULL", ( char *) ae->real_addr, ae->size + SIZE_CHECK_AREA * 2);
	}

	return 0;
}

int trc(const char *text, ...) {
	char insert[32000];
	va_list vl;

	va_start( vl, text);
	vsprintf( insert, text, vl);
	va_end( vl);

	fprintf( htc->heap_report, "[%d] - %s", getpid(), insert);
	fflush( htc->heap_report);
}

int trc_delimiter_line()
{
	trc( "\n----------------------------------------------------------------------------------------------------------------------------------------------------\n");
}
