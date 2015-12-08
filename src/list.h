/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2010 Sebastien Vincent <sebastien.vincent@turnserver.org>
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

/*
 * Copyright (C) 2006-2010 Sebastien Vincent.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * \file list.h
 * \brief Doubly linked list management.
 * \author Sebastien Vincent
 * \date 2006-2010
 */

#ifndef LIST_H
#define LIST_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(_MSC_VER) && !defined(__cplusplus)
/* Microsoft compiler does not know inline
 * keyword in a pure C program
 */
#define inline __inline
#endif

#include <stddef.h> /* for offsetof */

/**
 * \struct list_head
 * \brief Doubly linked list implementation.
 *
 * Simple doubly linked list implementation inspired by include/linux/list.h.
 * \note To use it: LIST_HEAD(name_variable) to declare the variable
 * then always do INIT_LIST(name_variable).
 */
typedef struct list_head
{
  struct list_head *next; /**< Next element in the list */
  struct list_head *prev; /**< Previous element in the list */
}list_head;

/**
 * \def INIT_LIST
 * \brief Initialize a list.
 * \param name the list to initialize
 */
#define INIT_LIST(name) do { \
  (name).prev = &(name); \
  (name).next = &(name); \
}while(0);

/**
 * \def LIST_HEAD
 * \brief Used to declare a doubly linked list.
 * \param name name of list_head struct
 */
#define LIST_HEAD(name) struct list_head name

/**
 * \def LIST_ADD
 * \brief Add a new entry after the specified head.
 * \param new_entry new entry to be added
 * \param head list head to add it after
 */
#define LIST_ADD(new_entry, head) do { \
  struct list_head* next = (head)->next; \
  next->prev = (new_entry); \
  (new_entry)->next = next; \
  (new_entry)->prev = (head); \
  (head)->next = (new_entry); \
}while(0);

/**
 * \def LIST_ADD_TAIL
 * \brief Add a new entry before the specified head.
 * \param new_entry new entry to be added
 * \param head list head to add it before
 */
#define LIST_ADD_TAIL(new_entry, head) do { \
  struct list_head* prev = (head)->prev; \
  (head)->prev = (new_entry); \
  (new_entry)->next = (head); \
  (new_entry)->prev = prev; \
  prev->next = (new_entry); \
}while(0);

/**
 * \def LIST_DEL
 * \brief Delete entry from list.
 * \param rem pointer of the element to delete from the list
 * \note list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
#define LIST_DEL(rem) do { \
  (rem)->next->prev = (rem)->prev; \
  (rem)->prev->next = (rem)->next; \
  (rem)->next = (rem); \
  (rem)->prev = (rem); \
}while(0);

/**
 * \def LIST_EMPTY
 * \brief Return whether or not the list is empty.
 * \param head pointer on the list to test
 * \return 1 if empty, 0 otherwise
 */
#define LIST_EMPTY(head) \
  ((head)->next == (head))

/**
 * \def list_get
 * \brief Get the element.
 * \param ptr the list_head pointer
 * \param type the type of the struct this is embedded in
 * \param member the name of the list_struct within the struct
 * \return pointer on the structure for this entry
 */
#define list_get(ptr, type, member) \
  (type *)((char *)(ptr) - offsetof(type, member))

/**
 * \def list_iterate
 * \brief Iterate over a list.
 * \param pos the &struct list_head to use as a loop counter
 * \param head the head for your list
 */
#define list_iterate(pos, head) \
  for((pos) = (head)->next ; (pos) != (head) ; (pos) = (pos)->next)

/**
 * \def list_iterate_safe
 * \brief Thread safe version to iterate over a list.
 * \param pos pointer on a list_head struct
 * \param n temporary variable
 * \param head the list.
 */
#define list_iterate_safe(pos, n, head) \
  for((pos) = (head)->next, (n) = (pos)->next ; (pos) != (head) ; \
      (pos) = (n), (n) = (pos)->next)

/**
 * \brief Get the number of element in the list.
 * \param head the list
 * \return size of the list
 */
static inline unsigned int list_size(struct list_head* head)
{
  struct list_head* lp = NULL;
  unsigned int size = 0;

  list_iterate(lp, head)
  {
    size++;
  }
  return size;
}

#endif /* LIST_H */

