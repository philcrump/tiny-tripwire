#ifndef __EMAIL_H__
#define __EMAIL_H__

#include <stdbool.h>
#include "config.h"

typedef struct {
  char *to;
  char *from;
  char *subject;
  char *message;
} email_t;

bool email(config_t *config_ptr, email_t *email_ptr);

#endif /* __EMAIL_H__ */
