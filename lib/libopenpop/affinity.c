/* Copyright (C) 2006-2017 Free Software Foundation, Inc.
   Contributed by Jakub Jelinek <jakub@redhat.com>.

   This file is part of the GNU Offloading and Multi Processing Library
   (libgomp).

   Libgomp is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   Libgomp is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
   more details.

   Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.

   You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */

/* This is a generic stub implementation of a CPU affinity setting.  */

#include "libgomp.h"
#include "hierarchy.h"
#include <assert.h>
#include "migrate.h"
#include "platform.h"

void
gomp_init_affinity (void)
{
}

#ifdef LIBGOMP_USE_PTHREADS
void
gomp_init_thread_affinity (pthread_attr_t *attr, unsigned int place)
{
  (void) attr;
  (void) place;
}
#endif

void **
gomp_affinity_alloc (unsigned long count, bool quiet)
{
  (void) count;
  if (!quiet)
    gomp_error ("Affinity not supported on this configuration");
  return NULL;
}

void
gomp_affinity_init_place (void *p)
{
  (void) p;
}

bool
gomp_affinity_add_cpus (void *p, unsigned long num,
			unsigned long len, long stride, bool quiet)
{
  (void) p;
  (void) num;
  (void) len;
  (void) stride;
  (void) quiet;
  return false;
}

bool
gomp_affinity_remove_cpu (void *p, unsigned long num)
{
  (void) p;
  (void) num;
  return false;
}

bool
gomp_affinity_copy_place (void *p, void *q, long stride)
{
  (void) p;
  (void) q;
  (void) stride;
  return false;
}

bool
gomp_affinity_same_place (void *p, void *q)
{
  (void) p;
  (void) q;
  return false;
}

bool
gomp_affinity_finalize_place_list (bool quiet)
{
  (void) quiet;
  return false;
}

bool
gomp_affinity_init_level (int level, unsigned long count, bool quiet)
{
  (void) level;
  (void) count;
  (void) quiet;
  if (!quiet)
    gomp_error ("Affinity not supported on this configuration");
  return NULL;
}

void
gomp_affinity_print_place (void *p)
{
  (void) p;
}

int
omp_get_place_num_procs (int place_num)
{
  (void) place_num;
  return 0;
}

void
omp_get_place_proc_ids (int place_num, int *ids)
{
  (void) place_num;
  (void) ids;
}

void
gomp_get_place_proc_ids_8 (int place_num, int64_t *ids)
{
  (void) place_num;
  (void) ids;
}

ialias(omp_get_place_num_procs)
ialias(omp_get_place_proc_ids)

/* Defined libmigrate.a (but not exposed in headers) */
extern void __init_nodes_info(void);

bool
popcorn_affinity_init_nodes (unsigned long count, bool quiet)
{
  int i;

  /* Make sure the migration library has populated node information */
  __init_nodes_info();

  for(i = 0; i < MAX_POPCORN_NODES; i++)
  {
    if(node_available(i))
    {
      popcorn_global.nodes++;
      popcorn_global.threads_per_node[i] = count;
      gomp_barrier_init(&popcorn_node[i].bar, count);
    }
  }

  if(popcorn_global.nodes)
  {
    popcorn_global.distributed = true;
    popcorn_global.hybrid_barrier = true;
    popcorn_global.hybrid_reduce = true;
    gomp_barrier_init(&popcorn_global.bar, popcorn_global.nodes);
  }
  else if(!quiet)
    gomp_error("No Popcorn nodes available");

  return popcorn_global.nodes;
}
