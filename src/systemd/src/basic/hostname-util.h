#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "macro.h"

bool hostname_is_set(void);

char* gethostname_malloc(void);
int gethostname_strict(char **ret);

bool hostname_is_valid(const char *s, bool allow_trailing_dot) _pure_;
char* hostname_cleanup(char *s);

#define machine_name_is_valid(s) hostname_is_valid(s, false)

bool is_localhost(const char *hostname);
bool is_gateway_hostname(const char *hostname);

int sethostname_idempotent(const char *s);

int read_hostname_config(const char *path, char **hostname);
