#ifdef __cplusplus
extern "C" {
#endif

#ifndef LIST_H
#define LIST_H

typedef struct cell *list;

struct cell
{
  void *element;
  list next;
};

extern list cons(void *element, list l);
extern list cdr_and_free(list l);

#endif

#ifdef __cplusplus
}
#endif
