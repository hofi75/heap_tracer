#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

#define __USE_TSEARCH

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

#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>

#define flag_set( _flag, _mask) \
   _flag |= _mask;
#define flag_reset( _flag, _mask) \
   _flag &= ~(_mask);
#define flag_test( _flag, _mask) \
   ( _flag & ( _mask))

#define SIZE_CHECK_AREA		32
#define SIZE_BACKTRACE		8192

typedef struct __allocate_entry {
	char 				eyec[4];
	unsigned long long 	id;
	void 				*addr;			// points to user memory
	void 				*real_addr;		// points to libc allocated memory
	void 				*trailer_cs;	// trailer check string
	size_t 				size;
	pid_t				pid;
	char 				checkstring[SIZE_CHECK_AREA];
	char 				backtrace[SIZE_BACKTRACE];
} allocate_entry_t;

typedef struct __heap_tracer_context {
#ifdef __USE_TSEARCH
	void				*troot;
#else
	allocate_entry_t 	*table;
#endif
	FILE 				*heap_report;
	int 				unused;
	int					entries;
	int					allocated;
	int 				max_entries;
	int 				max_size;
	int 				size;
	unsigned long long 	id;
	pthread_mutex_t 	lock;
	pid_t				start_pid;
	int 				flag;
#define	FLAG_ACTIVE				0x0001
#define	FLAG_TRACE_MODULE			0x0002
#define	FLAG_TRACE_HEAP_CALLS		0x0004
#define	FLAG_BACKTRACE				0x0008
#define	FLAG_CHECK_BOUNDARIES		0x0010
#define	FLAG_LOCKING				0x0020
	int 				flag_active;
	int 				flag_trace_calls;
	int 				flag_backtrace;
} heap_tracer_context_t;

#define is_active			flag_test( htc->flag, FLAG_ACTIVE)
#define is_trace_calls		flag_test( htc->flag, FLAG_TRACE_HEAP_CALLS)
#define is_trace_module		flag_test( htc->flag, FLAG_TRACE_MODULE)
#define is_backtrace		flag_test( htc->flag, FLAG_BACKTRACE)
#define is_check_boundaries	flag_test( htc->flag, FLAG_CHECK_BOUNDARIES)
#define is_locking			flag_test( htc->flag, FLAG_LOCKING)

static void prepare(void) __attribute__((constructor));
static void unload(void) __attribute__((destructor));

void generate_backtrace_string(char *result, const void *caller);

int set_checkstring	(allocate_entry_t *ae);
int check_boundaries(allocate_entry_t *ae);

int trc(const char *, ...);
void __dump(const char *title, char *addr, size_t len);

extern const char *__progname;
static	void *troot = NULL;

/* Prototypes for our hooks.  */
static void my_init_hook(void);
static void *my_malloc_hook(size_t, const void *);
static void *my_memalign_hook(size_t, size_t, const void *);
static void *my_realloc_hook(void *, size_t, const void *);
static void my_free_hook(void *, const void *);

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

static void prepare(void) {
	char *htenv, *p, temp[256], report_path[256];
	struct sigaction sa;

	memset( htc, 0, sizeof( heap_tracer_context_t));

	// check if our program name is defined in HEAP_TRACER
	htenv = getenv( HT_ENV);
	if (htenv) {
		char *d;

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

		if ((p = strstr(htenv, "trace_calls")) != NULL)
			flag_set(htc->flag, FLAG_TRACE_HEAP_CALLS);

		if ((p = strstr(htenv, "trace_module")) != NULL)
			flag_set(htc->flag, FLAG_TRACE_MODULE);

		if ((p = strstr(htenv, "backtrace")) != NULL)
			flag_set(htc->flag, FLAG_BACKTRACE);

		if ((p = strstr(htenv, "check_boundaries")) != NULL)
			flag_set(htc->flag, FLAG_CHECK_BOUNDARIES);

		if ((p = strstr(htenv, "locking")) != NULL)
			flag_set(htc->flag, FLAG_LOCKING);
	}

	flag_set(htc->flag, FLAG_ACTIVE);

	sprintf(temp, "%sheap_report_%s_%d.txt", report_path, __progname, getpid());
	if ((htc->heap_report = fopen(temp, "w+t")) == NULL) {
		printf("unable to create heap report (%s)\n", temp);
		exit(16);
	}

	trc( "heap trace file '%s' opened for\n\n", temp);
	trc( "\texecutable    = '%s'\n", __progname);
	trc( "\tenvironment   = '%s'\n", htenv);
	trc( "\tbacktracing   = %s\n", ( is_backtrace) ? "yes" : "no");
	trc( "\ttrace calls   = %s\n", ( is_trace_calls) ? "yes" : "no");
	trc( "\ttrace module  = %s\n", ( is_trace_module) ? "yes" : "no");
	trc( "\tbounday check = %s\n", ( is_check_boundaries) ? "yes" : "no");
	trc( "\tlock          = %s\n", ( is_locking) ? "yes" : "no");
	trc( "\n");

	if ( is_locking)
		pthread_mutex_init(&htc->lock, NULL);

	// allocate entries for allocate table
#ifndef __USE_TSEARCH
	htc->size = 64 * 1024;
	htc->table = (allocate_entry_t *) malloc( SIZE_TABLE);
	memset(htc->table, 0, SIZE_TABLE);
#endif

	htc->start_pid = getpid();

	hooks_backup();
	hooks_setmine();
}

static int ae_compare_id(const void *node1, const void *node2) {
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

	if ( is_trace_module)
	{
		trc( "compare -->\n");
		trc( "compare(%p,%p)\n", ae1, ae2);
		trc( "\taddr(%p <--> %p)\n", ae1->addr, ae2->addr);
	}

	if ( ae1->addr < ae2->addr)	rslt = -1;
	if ( ae1->addr > ae2->addr)	rslt = 1;

	if ( is_trace_module)
		trc( "compare result = %d\n", rslt);

	return rslt;
}

void ae_free_node( void *node)
{
	allocate_entry_t *ae = node;

	if ( ae->addr != NULL)
	{
		trc("[ID=%lld] area at %p with size %ld not freed (pid=%d)\n",
				ae->id, ae->addr, ae->size, ae->pid);
		trc("     backtrace = \n%s\n", ae->backtrace);
		__dump("AREA", ae->addr, ae->size);
	}

	free( node);
}



static void unload(void) {

	int i;
	size_t sum;
	allocate_entry_t *ae;

	if (!is_active) return;

	hooks_restore();

#ifdef __USE_TSEARCH
#else
	for (sum = i = 0, ae = htc->table; i < htc->unused; i++, ae += 1)
	{
		if (ae->addr == NULL) continue;
		sum += ae->size;
	}
#endif

	trc( "number of unallocated entries : %d\n", htc->entries);
	trc( "size   of unallocated entries : %ld MB\n",
			(long) (htc->allocated / (1024 * 1024)));

	trc( "max number of entries         : %d\n", htc->max_entries);
	trc( "max memory usage              : %ld MB\n", (long) (htc->max_size / (1024 * 1024)));


#ifdef __USE_TSEARCH
	tdestroy( troot, &ae_free_node);
#else
	trc( "sorting allocate table by ID...\n");
	qsort( (void *) htc->table, htc->unused, sizeof(allocate_entry_t),
			compare_ae);

	for (sum = i = 0, ae = htc->table; i < htc->unused; i++, ae += 1)
	{
		if (ae->addr == NULL) continue;

		trc("[%d][ID=%lld] area at %p with size %ld not freed\n", i, ae->id,
				ae->addr, ae->size);
		trc("     backtrace = %s\n", ae->backtrace);
		__dump("AREA", ae->addr, ae->size);
	}

	free(htc->table);
#endif

	fclose(htc->heap_report);
}

#define BACKTRACE_SIZE 24

void * array[BACKTRACE_SIZE * 4];

void generate_backtrace_string(char *result, const void *caller) {
	char **messages;
	char *p;
	int size, i, l, x;

	*result = '\0';
	if (!is_backtrace)
		return;

	if ( is_trace_module)
		trc("%s -->\n", __FUNCTION__);

	size = backtrace(array, BACKTRACE_SIZE);
	if ( is_trace_module)
		trc("\tbacktrace size = %d\n", size);

	messages = backtrace_symbols(array, size);

	for (l = SIZE_BACKTRACE, p = result, i = 2; i < size && messages[i] != NULL;
			++i) {
		x = snprintf( p, l - 1, "\t\t[[%d][%s]]\n", i, messages[i]);
		p += x;
		l -= x;
		if (l < 400)
			break;
	}
	free(messages);

	if ( is_trace_module)
		trc("%s <-- \n%s\n", __FUNCTION__, result);

}

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
	__malloc_hook = my_malloc_hook;
	__memalign_hook = my_memalign_hook;
	__realloc_hook = my_realloc_hook;
	__free_hook = my_free_hook;
}

#ifdef __USE_TSEARCH
allocate_entry_t * table_add_entry( char *addr, size_t size) {
	allocate_entry_t *new_ae, *ae;

	if ( is_trace_module)
		trc("%s(%p,%ld,troot=%p) -->\n", __FUNCTION__, addr, size, troot);

	// save in table
	new_ae = malloc( sizeof( allocate_entry_t));
	memcpy( new_ae->eyec, "%%AE", 4);
	new_ae->real_addr = addr;
	if ( is_check_boundaries) {
		new_ae->addr = addr + SIZE_CHECK_AREA;
		new_ae->trailer_cs = addr + size + SIZE_CHECK_AREA;
	} else
		new_ae->addr = addr;
	new_ae->size = size;
	new_ae->id = htc->id++;
	new_ae->pid = getpid();
	htc->entries++;
	htc->allocated += size;

	if ( htc->entries > htc->max_entries) htc->max_entries = htc->entries;
	if ( htc->allocated > htc->max_size) htc->max_size = htc->allocated;

	ae = *( allocate_entry_t **)
			tsearch( ( void *) new_ae, &(troot), &ae_compare_address);

	if ( is_trace_module)
		trc("%s <-- (new_ae=%p, ae=%p)\n", __FUNCTION__, new_ae, ae);

	return new_ae;
}
#else
allocate_entry_t * table_add_entry(char *addr, size_t size) {
	allocate_entry_t *new_ae, *ae;

	if ( is_trace_module)
		trc("%s(%p,%ld) -->\n", __FUNCTION__, addr, size);

	// save in table
	new_ae = htc->table + htc->unused;
	memcpy( new_ae->eyec, "%%AE", 4);
	new_ae->real_addr = addr;
	if ( is_check_boundaries) {
		new_ae->addr = addr + SIZE_CHECK_AREA;
		new_ae->trailer_cs = addr + size + SIZE_CHECK_AREA;
	} else
		new_ae->addr = addr;
	new_ae->size = size;
	new_ae->id = htc->id++;
	htc->unused++;

	if (htc->unused >= htc->size) {
		htc->size += 8192;
		htc->table = realloc(htc->table, SIZE_TABLE);
		trc("? allocate table re-allocated %d entries\n", htc->size);
		memset(htc->table + htc->unused, 0,
				sizeof(allocate_entry_t) * (htc->size - htc->unused));
	}

	if (htc->unused > htc->max) {
		htc->max = htc->unused;
		if (htc->max % 1024 == 0)
			trc("max allocated entries reached %d\n", htc->max);
	}

	if ( is_trace_module)
		trc("%s <-- (ae=%p)\n", __FUNCTION__, ae);

	return ae;
}
#endif

#ifdef __USE_TSEARCH
void * table_remove_entry( void *addr, const char *backtrace)
{
	int 			 i, found = 0;
	allocate_entry_t	ssearch_ae;
	allocate_entry_t 	*search_ae = &ssearch_ae, *ae;
	void				*rslt;

	if ( is_trace_module)
		trc("%s(%p,troot=%p) -->\n", __FUNCTION__, addr, troot);

	if ( addr == NULL) return NULL;
	/* search by address */
	memset( search_ae, 0, sizeof( allocate_entry_t));
	search_ae->addr = addr;
	if ( is_trace_module)
		trc("tfind(search_ae=%p,addr=%p)\n", search_ae, search_ae->addr);
	void *x = tfind( ( void *) search_ae, &(troot), &ae_compare_address);
	if ( !x)
	{
		trc("? (FREE/REALLOC)(NOT FOUND) - / %p  ==> \n%s\n", addr, backtrace);
		return NULL;
	}
	ae = *( allocate_entry_t **) x;
	if ( is_trace_module)
		trc("tdelete(search_ae=%p,addr=%p)\n", ae, ae->addr);
	tdelete( ( void *) ae, &(troot), &ae_compare_address);
	rslt = ae->real_addr;
	htc->entries--;
	if ( htc->entries > htc->max_entries) htc->max_entries = htc->entries;
	htc->allocated -= ae->size;
	if ( htc->allocated > htc->max_size) htc->max_size = htc->allocated;
	free( ae);

	if ( is_trace_module)
		trc("%s <-- (rslt=%p)\n", __FUNCTION__, rslt);

	return rslt;
}
#else
void * table_remove_entry(void *addr, const char *backtrace)
{
	int 			 i, found = 0;
	allocate_entry_t *ae = alloca( sizeof( allocate_entry_t)), *rslt;

	if ( is_trace_module)
		trc("%s(%p) -->\n", __FUNCTION__, addr);

	if ( addr == NULL) return rslt;

	for (i = 0, ae = htc->table; i < htc->unused; i++, ae += 1) {
		if (ae->addr != addr) continue;

		check_boundaries(ae);

		rslt = ae->real_addr;

		// replace entry with last entry in table
		htc->unused--;
		memcpy(ae, htc->table + htc->unused, sizeof(*ae));
		memset(htc->table + htc->unused, 0, sizeof(*ae));
		found = 1;
		break;
	}

	if (!found)
		trc("? (FREE/REALLOC)(NOT FOUND) - / %p  ==> %s\n", addr, backtrace);

	if ( is_trace_module)
		trc("%s <-- (rslt=%p)\n", __FUNCTION__, rslt);

	return rslt;
}
#endif

static void *my_malloc_hook(size_t size, const void *caller)
{
	char *addr;
	allocate_entry_t *ae;
	size_t alloc_size;

	if ( is_locking)
		pthread_mutex_lock(&htc->lock);

	hooks_restore();

	if ( is_trace_module)
		trc("%s( %ld) -->\n", __FUNCTION__, size);

	alloc_size = size;
	if ( is_check_boundaries)
		alloc_size += SIZE_CHECK_AREA * 2;

	if (old_malloc_hook != NULL)
		addr = (__ptr_t) (*old_malloc_hook)( alloc_size, caller);
	else
		addr = (__ptr_t) malloc( alloc_size);

	ae = table_add_entry( addr, size);
	generate_backtrace_string( ae->backtrace, caller);

	if ( is_trace_calls)
		trc("+ (MALLOC)  %10ld / %8p  ==> \n%s\n", size, ae->addr, ae->backtrace);

	set_checkstring( ae);

	if ( is_trace_module)
		trc("%s() <-- %p\n", __FUNCTION__, addr);

	hooks_setmine();

	if ( is_locking)
		pthread_mutex_unlock(&htc->lock);

	// return address
	return ae->addr;
}

static void *my_memalign_hook(size_t alignment, size_t size, const void *caller) {
	char *addr;
	allocate_entry_t *ae;
	size_t alloc_size;

	if ( is_locking)
		pthread_mutex_lock(&htc->lock);
	hooks_restore();

	if ( is_trace_module)
		trc("%s( %d, %ld) -->\n", __FUNCTION__, alignment, size);

	if ( is_check_boundaries)
		alloc_size = size + SIZE_CHECK_AREA * 2;
	else
		alloc_size = size;

	if (old_memalign_hook != NULL)
		addr = (__ptr_t) (*old_memalign_hook)(alignment, alloc_size, caller);
	else
		addr = (__ptr_t) memalign( alignment, alloc_size);

	ae = table_add_entry( addr, size);
	generate_backtrace_string( ae->backtrace, caller);
	set_checkstring( ae);

	if ( is_trace_calls)
		trc("+ (MEMALIGN) %10ld / %8p  ==> \n%s\n", size, ae->addr,
				ae->backtrace);

	if ( is_trace_module)
		trc("%s( %d, %ld) <-- %p\n", __FUNCTION__, alignment, size, addr);

	hooks_setmine();

	if ( is_locking)
		pthread_mutex_unlock(&htc->lock);

	return ae->addr;
}

static void *my_realloc_hook(void *ptr, size_t size, const void *caller)
{
	void 				*addr;
	allocate_entry_t 	*ae;
	size_t 				alloc_size;
	char 				bts[8192];

	if ( is_locking)
		pthread_mutex_lock(&htc->lock);
	hooks_restore();

	if ( is_trace_module)
		trc("%s( %p, %ld) -->\n", __FUNCTION__, ptr, size);

	generate_backtrace_string( bts, caller);
	addr = table_remove_entry( ptr, bts);

	if ( is_check_boundaries)
		alloc_size = size + SIZE_CHECK_AREA * 2;
	else
		alloc_size = size;

	if (old_realloc_hook != NULL)
		addr = (__ptr_t) (*old_realloc_hook)( addr, alloc_size, caller);
	else
		addr = (__ptr_t) realloc( addr, alloc_size);

	ae = table_add_entry( addr, size);
	generate_backtrace_string( ae->backtrace, caller);

	if ( is_trace_calls) {
		trc("- (REALLOC)          - / %8p  ==> \n%s\n", ptr, ae->backtrace);
		trc("+ (REALLOC) %10ld / %8p  ==> \n%s\n", size, ae->addr, ae->backtrace);
	}

	set_checkstring( ae);
	if ( is_trace_module)
		trc("%s( %p, %ld) <-- %p\n", __FUNCTION__, ptr, size, ae->addr);

	hooks_setmine();
	if ( is_locking)
		pthread_mutex_unlock(&htc->lock);

	return ae->addr;
}

/*
int	check_pid()
{
	if ( htc->start_pid == getpid()) return 0;
	hooks_restore();

	tdestroy( troot, &ae_free_node);
	fclose( htc->heap_report);

	return 0;
}
*/
static void my_free_hook(void *ptr, const void *caller)
{
	char 	bts[8192];
	void	*addr;

	if ( is_locking)
		pthread_mutex_lock(&htc->lock);
	hooks_restore();

	if ( is_trace_module)
		trc("%s( %p) -->\n", __FUNCTION__, ptr);

	generate_backtrace_string( bts, caller);
	addr = table_remove_entry( ptr, bts);

	if (old_free_hook != NULL)
		(*old_free_hook)( addr, caller);
	else
		free( addr);

	if ( is_trace_calls)
		trc("- (FREE)             - / %8p  ==> \n%s\n", addr, bts);

	if ( is_trace_module)
		trc("%s( %p) <--\n", __FUNCTION__, addr);

	hooks_setmine();

	if ( is_locking)
		pthread_mutex_unlock( &htc->lock);
}

void __dump(const char *title, char *addr, size_t len) {
	int i, m;
	char s1[256], s2[256], s3[256], s4[2];
	unsigned char *p = (unsigned char *) addr;

	trc("DUMPING(%s): %p(%ld)\n", title, addr, len);

	if (len > 65536) {
		len = 65536;
		trc("\t\tsize cut to 65536\n");
	}

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

	if ( ae->real_addr == NULL)  return 0;

	sprintf(temp, "#*#*%p<***>%.10ld#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*",
				ae->addr, ae->size);
	memcpy( ae->checkstring, temp, SIZE_CHECK_AREA);
	memcpy( ae->real_addr, ae->checkstring, SIZE_CHECK_AREA);
	memcpy( ae->trailer_cs, ae->checkstring, SIZE_CHECK_AREA);

	return 0;
}

int check_boundaries(allocate_entry_t *ae) {
	int corrupted = 0;

	if (!is_check_boundaries) return 0;

	if (ae == NULL)	return 0;

	if (ae->real_addr == NULL) return 0;

	if ( memcmp(ae->real_addr, ae->checkstring, SIZE_CHECK_AREA) != 0) {
		trc("memory buffer HEADER check string corrupted...\n");
		corrupted = 1;
	}

	if ( memcmp( ae->trailer_cs, ae->checkstring, SIZE_CHECK_AREA) != 0) {
		trc("memory buffer TRAILER check string corrupted...\n");
		corrupted = 1;
	}

	if ( corrupted) {
		trc( "\taddr      = %p\n", ae->addr);
		trc( "\treal addr = %p\n", ae->real_addr);
		trc( "\tsize      = %ld\n", ae->size);
		trc( "\nbacktrace = %s\n", ae->backtrace);
		__dump("CHECKSTRING", ae->checkstring, SIZE_CHECK_AREA);
		__dump("HEADER", ae->real_addr, SIZE_CHECK_AREA);
		__dump("TRAILER", ae->trailer_cs, SIZE_CHECK_AREA);
		__dump("FULL", ae->real_addr, ae->size + SIZE_CHECK_AREA * 2);
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
