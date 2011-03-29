/**
 * @file src/include/list.h
 * @brief Simple doubly linked list implementation
 */

/*
 * Copyright (C) 2008 Karel Zak <kzak@redhat.com>
 * Copyright (C) 1999-2008 by Theodore Ts'o
 *
 * (based on list.h from e2fsprogs)
 *
 * This file is part of fedfs-utils, and was copied from util-linux.
 *
 * fedfs-utils is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2.0 as
 * published by the Free Software Foundation.
 *
 * fedfs-utils is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2.0 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2.0 along with fedfs-utils.  If not, see:
 *
 *	http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 */

#ifndef _FEDFS_LIST_H_
#define _FEDFS_LIST_H_

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

/**
 * Anchor for doubly linked lists
 */
struct list_head {
	struct list_head *next, *prev;
};

/**
 * Initialized list_head structure (R-value)
 */
#define LIST_HEAD_INIT(name) { &(name), &(name) }

/**
 * Initialize a list_head structure at definition time
 */
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

/**
 * Initialize a list_head structure in function bodies
 */
#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/**
 * Insert a new entry between two known consecutive entries
 *
 * @param add
 * @param prev
 * @param next
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void
__list_add(struct list_head *add, struct list_head *prev,
		struct list_head *next)
{
	next->prev = add;
	add->next = next;
	add->prev = prev;
	prev->next = add;
}

/**
 * Add a new entry
 *
 * @param add new entry to be added
 * @param head list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void
list_add(struct list_head *add, struct list_head *head)
{
	__list_add(add, head, head->next);
}

/**
 * Add a new entry
 *
 * @param add new entry to be added
 * @param head list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void
list_add_tail(struct list_head *add, struct list_head *head)
{
	__list_add(add, head->prev, head);
}

/**
 * Delete a list entry by making the prev/next entries * point to each other
 *
 * @param prev
 * @param next
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void
__list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * Deletes entry from list
 *
 * @param entry the element to delete from the list
 *
 * list_empty() on "entry" does not return true after this, "entry" is
 * in an undefined state.
 */
static inline void
list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

/**
 * Deletes entry from list and reinitialize it
 *
 * @param entry the element to delete from the list
 */
static inline void
list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

/**
 * Predicate: is list empty?
 *
 * @param head the list to test
 * @return true if list is empty
 */
static inline _Bool
list_empty(const struct list_head *head)
{
	return head->next == head;
}

/**
 * Predicate: is entry last in list?
 *
 * @param entry the entry to test
 * @param head the list to test
 * @return true if "entry" is last in list
 */
static inline _Bool
list_last_entry(const struct list_head *entry, const struct list_head *head)
{
	return head->prev == entry;
}

/**
 * Join two lists
 *
 * @param list the new list to add
 * @param head the place to add it in the first list
 */
static inline void
list_splice(struct list_head *list, struct list_head *head)
{
	struct list_head *first = list->next;

	if (first != list) {
		struct list_head *last = list->prev;
		struct list_head *at = head->next;

		first->prev = head;
		head->next = first;

		last->next = at;
		at->prev = last;
	}
}

/**
 * Get the struct for this entry
 */
#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * Iterate over elements in a list
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * Iterate over elements in a list in reverse
 */
#define list_for_each_backwardly(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * Iterate over elements in a list, but don't dereference pos after the body is done (in case it is freed)
 */
#define list_for_each_safe(pos, pnext, head) \
	for (pos = (head)->next, pnext = pos->next; pos != (head); \
	     pos = pnext, pnext = pos->next)

#endif /* !_FEDFS_LIST_H_ */
