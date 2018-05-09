//
// Created by rc452 on 2018/5/4.
//

#ifndef BADVPN_BASIC_H
#define BADVPN_BASIC_H

#include <stdint.h>
#include <stdio.h>

#if defined(__GNUC__)
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)      (x)
#define unlikely(x)    (x)
#endif

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#define sleep(x) Sleep((x)*1000)
#define random rand
#define srandom srand
#endif

/* bool definitions */
#define bool int
#define true 1
#define false 0

/* size of an array */
#define SIZE(x) (sizeof(x)/sizeof(x[0]))

/* clear an object (may be optimized away, use secure_memzero() to erase secrets) */
#define CLEAR(x) memset(&(x), 0, sizeof(x))



#if defined(__GNUC__)
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)      (x)
#define unlikely(x)    (x)
#endif

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#define sleep(x) Sleep((x)*1000)
#define random rand
#define srandom srand
#endif
/**************************************************************************/
/**
 * Wrapper structure for dynamically allocated memory.
 *
 * The actual content stored in a \c buffer structure starts at the memory
 * location \c buffer.data \c + \c buffer.offset, and has a length of \c
 * buffer.len bytes.  This, together with the space available before and
 * after the content, is represented in the pseudocode below:
 * @code
 * uint8_t *content_start    = buffer.data + buffer.offset;
 * uint8_t *content_end      = buffer.data + buffer.offset + buffer.len;
 * int      prepend_capacity = buffer.offset;
 * int      append_capacity  = buffer.capacity - (buffer.offset + buffer.len);
 * @endcode
 */
struct buffer
{
    int capacity;               /**< Size in bytes of memory allocated by
                                 *   \c malloc(). */
    int offset;                 /**< Offset in bytes of the actual content
                                 *   within the allocated memory. */
    int len;                    /**< Length in bytes of the actual content
                                 *   within the allocated memory. */
    uint8_t *data;              /**< Pointer to the allocated memory. */

#ifdef BUF_INIT_TRACKING
    const char *debug_file;
    int debug_line;
#endif
};

/**************************************************************************/
/**
 * Garbage collection entry for one dynamically allocated block of memory.
 *
 * This structure represents one link in the linked list contained in a \c
 * gc_arena structure.  Each time the \c gc_malloc() function is called,
 * it allocates \c sizeof(gc_entry) + the requested number of bytes.  The
 * \c gc_entry is then stored as a header in front of the memory address
 * returned to the caller.
 */
struct gc_entry {
    struct gc_entry *next;      /**< Pointer to the next item in the
                                 *   linked list. */
};

/**
 * Garbage collection entry for a specially allocated structure that needs
 * a custom free function to be freed like struct addrinfo
 *
 */
struct gc_entry_special {
    struct gc_entry_special *next;

    void (*free_fnc)(void *);

    void *addr;
};


/**
 * Garbage collection arena used to keep track of dynamically allocated
 * memory.
 *
 * This structure contains a linked list of \c gc_entry structures.  When
 * a block of memory is allocated using the \c gc_malloc() function, the
 * allocation is registered in the function's \c gc_arena argument.  All
 * the dynamically allocated memory registered in a \c gc_arena can be
 * freed using the \c gc_free() function.
 */
struct gc_arena {
    struct gc_entry *list;      /**< First element of the linked list of
                                 *   \c gc_entry structures. */
    struct gc_entry_special *list_special;
};



void x_gc_free(struct gc_arena *a);

void x_gc_freespecial(struct gc_arena *a);


static inline void
gc_init(struct gc_arena *a)
{
    a->list = NULL;
    a->list_special = NULL;
}

static inline struct gc_arena
gc_new(void) {
    struct gc_arena ret;
    gc_init(&ret);
    return ret;
}

static inline void
gc_free(struct gc_arena *a) {
    if (a->list) {
        x_gc_free(a);
    }
    if (a->list_special) {
        x_gc_freespecial(a);
    }
}

static inline void
gc_reset(struct gc_arena *a) {
    gc_free(a);
}


static inline void
check_malloc_return(const void *p)
{
    if (!p)
    {
        printf("out of memory");
    }
}

void *gc_malloc(size_t size, struct gc_arena *a){
    void *ret;
    if (a)
    {
        struct gc_entry *e;
        e = (struct gc_entry *) malloc(size + sizeof(struct gc_entry));
        check_malloc_return(e);
        ret = (char *) e + sizeof(struct gc_entry);
        e->next = a->list;
        a->list = e;
    }
    else
    {
        ret = malloc(size);
        check_malloc_return(ret);
    }
        memset(ret, 0, size);
    return ret;
}

void
x_gc_free(struct gc_arena *a)
{
    struct gc_entry *e;
    e = a->list;
    a->list = NULL;

    while (e != NULL)
    {
        struct gc_entry *next = e->next;
        free(e);
        e = next;
    }
}

/*
 * Functions to handle special objects in gc_entries
 */

void
x_gc_freespecial(struct gc_arena *a)
{
    struct gc_entry_special *e;
    e = a->list_special;
    a->list_special = NULL;

    while (e != NULL)
    {
        struct gc_entry_special *next = e->next;
        e->free_fnc(e->addr);
        free(e);
        e = next;
    }
}



/******************buffer********************/
#define BUF_SIZE_MAX 1000000
#define BPTR(buf)  (buf_bptr(buf))
#define BEND(buf)  (buf_bend(buf))
#define BLAST(buf) (buf_blast(buf))
#define BLEN(buf)  (buf_len(buf))
#define BDEF(buf)  (buf_defined(buf))
#define BSTR(buf)  (buf_str(buf))
#define BCAP(buf)  (buf_forward_capacity(buf))

struct buffer alloc_buf_gc(size_t size, struct gc_arena *gc);
static inline bool buf_size_valid(const size_t size);
void buf_size_error(const size_t size);
bool buf_printf(struct buffer *buf, const char *format, ...);
static inline bool buf_defined(const struct buffer *buf);
static inline uint8_t *buf_bptr(const struct buffer *buf);
static inline uint8_t *buf_bend(const struct buffer *buf);
static inline uint8_t *buf_blast(const struct buffer *buf);
static int buf_len(const struct buffer *buf);
static inline bool buf_defined(const struct buffer *buf);
static inline char *buf_str(const struct buffer *buf);
static inline int buf_forward_capacity(const struct buffer *buf);
static inline bool buf_valid(const struct buffer *buf);

static inline bool
buf_size_valid(const size_t size)
{
    return likely(size < BUF_SIZE_MAX);
}

struct buffer alloc_buf_gc(size_t size, struct gc_arena *gc){
    struct buffer buf;
    if (!buf_size_valid(size))
    {
        buf_size_error(size);
    }
    buf.capacity = (int)size;
    buf.offset = 0;
    buf.len = 0;

    buf.data = (uint8_t *) gc_malloc(size, gc);
    if (size)
    {
        *buf.data = 0;
    }
    return buf;
}

void
buf_size_error(const size_t size)
{
    printf("fatal buffer size error, size=%lu", (unsigned long)size);
}

bool
buf_printf(struct buffer *buf, const char *format, ...)
{
    int ret = false;
    if (buf_defined(buf))
    {
        va_list arglist;
        uint8_t *ptr = BEND(buf);
        int cap = buf_forward_capacity(buf);

        if (cap > 0)
        {
            int stat;
            va_start(arglist, format);
            stat = vsnprintf((char *)ptr, cap, format, arglist);
            va_end(arglist);
            *(buf->data + buf->capacity - 1) = 0; /* windows vsnprintf needs this */
            buf->len += (int) strlen((char *)ptr);
            if (stat >= 0 && stat < cap)
            {
                ret = true;
            }
        }
    }
    return ret;
}
static inline uint8_t *
buf_bptr(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        return buf->data + buf->offset;
    }
    else
    {
        return NULL;
    }
}

static inline bool
buf_defined(const struct buffer *buf)
{
    return buf->data != NULL;
}

static inline uint8_t *
buf_bend(const struct buffer *buf)
{
    return buf_bptr(buf) + buf_len(buf);
}

static inline uint8_t *
buf_blast(const struct buffer *buf)
{
    if (buf_len(buf) > 0)
    {
        return buf_bptr(buf) + buf_len(buf) - 1;
    }
    else
    {
        return NULL;
    }
}

static int
buf_len(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        return buf->len;
    }
    else
    {
        return 0;
    }
}

static inline char *
buf_str(const struct buffer *buf)
{
    return (char *)buf_bptr(buf);
}

static inline int
buf_forward_capacity(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        int ret = buf->capacity - (buf->offset + buf->len);
        if (ret < 0)
        {
            ret = 0;
        }
        return ret;
    }
    else
    {
        return 0;
    }
}
static inline bool
buf_valid(const struct buffer *buf)
{
    return likely(buf->data != NULL) && likely(buf->len >= 0);
}

/********************msg************************/

void
x_msg(const unsigned int flags, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    x_msg_va(flags, format, arglist);
    va_end(arglist);
}

void
x_msg_va(const unsigned int flags, const char *format, va_list arglist)
{
    struct gc_arena gc;

    char *m1;
    char *m2;
    char *tmp;
    int e;
    const char *prefix;
    const char *prefix_sep;

    void usage_small(void);



    e = openvpn_errno();

    /*
     * Apply muting filter.y
     */
#ifndef HAVE_VARARG_MACROS
    /* the macro has checked this otherwise */
    if (!dont_mute(flags))
    {
        return;
    }
#endif

    gc_init(&gc);

    m1 = (char *) gc_malloc(ERR_BUF_SIZE, false, &gc);
    m2 = (char *) gc_malloc(ERR_BUF_SIZE, false, &gc);

    vsnprintf(m1, ERR_BUF_SIZE, format, arglist);
    m1[ERR_BUF_SIZE - 1] = 0; /* windows vsnprintf needs this */

    if ((flags & M_ERRNO) && e)
    {
        openvpn_snprintf(m2, ERR_BUF_SIZE, "%s: %s (errno=%d)",
                         m1, strerror(e), e);
        SWAP;
    }

    if (flags & M_OPTERR)
    {
        openvpn_snprintf(m2, ERR_BUF_SIZE, "Options error: %s", m1);
        SWAP;
    }

#if SYSLOG_CAPABILITY
    if (flags & (M_FATAL|M_NONFATAL|M_USAGE_SMALL))
    {
        level = LOG_ERR;
    }
    else if (flags & M_WARN)
    {
        level = LOG_WARNING;
    }
    else
    {
        level = LOG_NOTICE;
    }
#endif

    /* set up client prefix */
    if (flags & M_NOIPREFIX)
    {
        prefix = NULL;
    }
    else
    {
        prefix = msg_get_prefix();
    }
    prefix_sep = " ";
    if (!prefix)
    {
        prefix_sep = prefix = "";
    }

    /* virtual output capability used to copy output to management subsystem */
    if (!forked)
    {
        const struct virtual_output *vo = msg_get_virtual_output();
        if (vo)
        {
            openvpn_snprintf(m2, ERR_BUF_SIZE, "%s%s%s",
                             prefix,
                             prefix_sep,
                             m1);
            virtual_output_print(vo, flags, m2);
        }
    }

    if (!(flags & M_MSG_VIRT_OUT))
    {
        if (use_syslog && !std_redir && !forked)
        {
#if SYSLOG_CAPABILITY
            syslog(level, "%s%s%s",
                   prefix,
                   prefix_sep,
                   m1);
#endif
        }
        else
        {
            FILE *fp = msg_fp(flags);
            const bool show_usec = check_debug_level(DEBUG_LEVEL_USEC_TIME);

            if (machine_readable_output)
            {
                struct timeval tv;
                gettimeofday(&tv, NULL);

                fprintf(fp, "%"PRIi64".%06ld %x %s%s%s%s",
                        (int64_t)tv.tv_sec,
                        (long)tv.tv_usec,
                        flags,
                        prefix,
                        prefix_sep,
                        m1,
                        "\n");

            }
            else if ((flags & M_NOPREFIX) || suppress_timestamps)
            {
                fprintf(fp, "%s%s%s%s",
                        prefix,
                        prefix_sep,
                        m1,
                        (flags&M_NOLF) ? "" : "\n");
            }
            else
            {
                fprintf(fp, "%s %s%s%s%s",
                        time_string(0, 0, show_usec, &gc),
                        prefix,
                        prefix_sep,
                        m1,
                        (flags&M_NOLF) ? "" : "\n");
            }
            fflush(fp);
            ++x_msg_line_num;
        }
    }

    if (flags & M_FATAL)
    {
        msg(M_INFO, "Exiting due to fatal error");
    }

    if (flags & M_FATAL)
    {
        openvpn_exit(OPENVPN_EXIT_STATUS_ERROR); /* exit point */

    }
    if (flags & M_USAGE_SMALL)
    {
        usage_small();
    }

    gc_free(&gc);
}

#endif //BADVPN_BASIC_H
