#ifndef _MY_LIST_H_
#define _MY_LIST_H_

#include <linux/list.h>
#include <linux/mm_types.h>

//#define MY_LIST_DEBUG


#define list_to_page(head) (list_entry(head, struct page, lru))

/* singly-linked list */
typedef struct _list {
  struct list_head *head;
  int num;
} LIST;

void list_insert(LIST *list, struct page *pg);
struct page *list_remove(LIST *list);

#endif

/* vi: set et sw=2 sts=2: */
