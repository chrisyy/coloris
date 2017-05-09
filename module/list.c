/*
 *  Copyright (C) 2013-2014  Ying Ye, PhD Candidate, Boston University
 *  Advisor: Richard West
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include "list.h"


/* insert a node at the head and return it 
 * this is better than inserting at the end
 * because of cache effect
 */
void list_insert(LIST *list, struct page *pg) {

  pg->lru.next = list->head;
  list->head = &pg->lru;

  list->num = list->num + 1;
}

/* remove the first node and return it */
struct page *list_remove(LIST *list) {

  struct page *pg;

  pg = list_to_page(list->head);
  list->head = pg->lru.next;

  list->num = list->num - 1;
  pg->lru.next = LIST_POISON1;
  return pg;
}

/* vi: set et sw=2 sts=2: */
