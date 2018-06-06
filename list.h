/*
* Copyright (C) Mellanox Technologies Ltd. 2001-2018.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef LIST_H_
#define LIST_H_

/**
 * A link in a circular list.
 */
typedef struct list_link {
    struct list_link  *prev;
    struct list_link  *next;
} list_link_t;


#ifndef container_of
#  define _offsetof(_type, _member) \
      ((unsigned long)&( ((_type*)0)->_member ))
#  define container_of(_ptr, _type, _member) \
      ( (_type*)( (char*)(void*)(_ptr) - _offsetof(_type, _member) )  )
#endif


#define LIST_INITIALIZER(_prev, _next) \
    { (_prev), (_next) }


/**
 * Declare an empty list
 */
#define LIST_HEAD(name) \
    list_link_t name = LIST_INITIALIZER(&(name), &(name))


/**
 * Initialize list head.
 *
 * @param head  List head struct to initialize.
 */
static inline void list_head_init(list_link_t *head)
{
    head->prev = head->next = head;
}

/**
 * Insert an element in-between to list elements. Any elements which were in this
 * section will be discarded.
 *
 * @param prev Element to insert after
 * @param next Element to insert before.
 */
static inline void list_insert_replace(list_link_t *prev,
                                           list_link_t *next,
                                           list_link_t *elem)
{
    elem->prev = prev;
    elem->next = next;
    prev->next = elem;
    next->prev = elem;
}

/**
 * Insert an item to a list after another item.
 *
 * @param pos         Item after which to insert.
 * @param new_link    Item to insert.
 */
static inline void list_insert_after(list_link_t *pos,
                                         list_link_t *new_link)
{
    list_insert_replace(pos, pos->next, new_link);
}

/**
 * Insert an item to a list before another item.
 *
 * @param pos         Item before which to insert.
 * @param new_link    Item to insert.
 */
static inline void list_insert_before(list_link_t *pos,
                                          list_link_t *new_link)
{
    list_insert_replace(pos->prev, pos, new_link);
}

/**
 * Remove an item from its list.
 *
 * @param link  Item to remove.
 */
static inline void list_del(list_link_t *link)
{
    link->prev->next = link->next;
    link->next->prev = link->prev;
}

/**
 * @return Whether the list is empty.
 */
static inline int list_is_empty(list_link_t *head)
{
    return head->next == head;
}

/*
 * Convenience macros
 */
#define list_add_head(_head, _item) \
    list_insert_after(_head, _item)
#define list_add_tail(_head, _item) \
    list_insert_before(_head, _item)


/**
 * Extract list head
 */
#define list_extract_head(_head, _type, _member) \
    ({ \
        list_link_t *tmp = (_head)->next; \
        list_del(tmp); \
        container_of(tmp, _type, _member); \
    })

#endif
