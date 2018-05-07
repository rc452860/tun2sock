//
// Created by rc452 on 2018/5/4.
//

#ifndef BADVPN_BASIC_H
#define BADVPN_BASIC_H

#include <stdint.h>
#include <stdio.h>

/* bool definitions */
#define bool int
#define true 1
#define false 0

/* size of an array */
#define SIZE(x) (sizeof(x)/sizeof(x[0]))

/* clear an object (may be optimized away, use secure_memzero() to erase secrets) */
#define CLEAR(x) memset(&(x), 0, sizeof(x))



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




#endif //BADVPN_BASIC_H
