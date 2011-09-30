/****************************************************************************
 * Copyright (C) 2009, 2010, 2011, 2012 by Kapil Arya, Gene Cooperman,      *
 *                                     Tyler Denniston, and Ana-Maria Visan *
 * {kapil,gene,tyler,amvisan}@ccs.neu.edu                                   *
 *                                                                          *
 * This file is part of FReD.                                               *
 *                                                                          *
 * FReD is free software: you can redistribute it and/or modify             *
 * it under the terms of the GNU General Public License as published by     *
 * the Free Software Foundation, either version 3 of the License, or        *
 * (at your option) any later version.                                      *
 *                                                                          *
 * FReD is distributed in the hope that it will be useful,                  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of           *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 * GNU General Public License for more details.                             *
 *                                                                          *
 * You should have received a copy of the GNU General Public License        *
 * along with FReD.  If not, see <http://www.gnu.org/licenses/>.            *
 ****************************************************************************/
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include "constants.h"
#include "trampolines.h"
#include "fred_wrappers.h"
#include "synchronizationlogging.h"

static trampoline_info_t mmap_trampoline_info;
static trampoline_info_t malloc_trampoline_info;
static trampoline_info_t calloc_trampoline_info;
static trampoline_info_t realloc_trampoline_info;
static trampoline_info_t free_trampoline_info;
static trampoline_info_t memalign_trampoline_info;

extern "C" void *fred_calloc(size_t nmemb, size_t size);
extern "C" void *fred_malloc(size_t size);
extern "C" void fred_free(void *ptr);
extern "C" void *fred_libc_memalign(size_t boundary, size_t size);
extern "C" void *fred_realloc(void *ptr, size_t size);

extern "C" void *memalign(size_t boundary, size_t size);

/* Used by _mmap_no_sync(). */
__attribute__ ((visibility ("hidden"))) __thread int mmap_no_sync = 0;
__attribute__ ((visibility ("hidden"))) __thread int malloc_no_sync = 0;

/* This could either be a normal dmtcp wrapper, or a hook function which calls
   a normal dmtcp wrapper. In this case, this is just a hook function which
   calls the real mmap wrapper (in mallocwrappers.cpp). I did it this way so
   that the real mmap wrapper could be relatively unchanged. Also, this way the
   default is to go through the regular mmap wrapper, and only if a call to
   mmap misses the wrapper does it go through the trampoline maze. */
static void *mmap_wrapper(void *addr, size_t length, int prot,
                          int flags, int fd, off_t offset)
{
  void *retval;
  if (IN_MMAP_WRAPPER || MMAP_NO_SYNC) {
    retval = _real_mmap(addr,length,prot,flags,fd,offset);
  } else {
    retval = mmap(addr,length,prot,flags,fd,offset);
  }
  return retval;
}

/* Calls to mmap will land here. */
static void *mmap_trampoline(void *addr, size_t length, int prot,
                             int flags, int fd, off_t offset)
{
  /* Interesting note: we get the arguments set up for free, since mmap is
     patched to jump directly to this function. */
  /* Unpatch mmap. */
  UNINSTALL_TRAMPOLINE(mmap_trampoline_info);
  /* Call mmap mini trampoline, which will eventually call _real_mmap. */
  void *retval = mmap_wrapper(addr,length,prot,flags,fd,offset);
  /* Repatch mmap. */
  INSTALL_TRAMPOLINE(mmap_trampoline_info);
  return retval;
}

static void *malloc_trampoline(size_t size)
{
  UNINSTALL_TRAMPOLINE(malloc_trampoline_info);

  void *retval;
  if (IN_MALLOC_WRAPPER) {
    retval = malloc(size);
  } else {
    retval = fred_malloc(size);
  }

  INSTALL_TRAMPOLINE(malloc_trampoline_info);
  return retval;
}

static void *memalign_trampoline(size_t alignment, size_t size)
{
  UNINSTALL_TRAMPOLINE(memalign_trampoline_info);

  void *retval;
  if (IN_MALLOC_WRAPPER) {
    retval = memalign(alignment, size);
  } else {
    retval = fred_libc_memalign(alignment, size);
  }

  INSTALL_TRAMPOLINE(memalign_trampoline_info);
  return retval;
}

static void *calloc_trampoline(size_t num, size_t size)
{
  UNINSTALL_TRAMPOLINE(calloc_trampoline_info);

  void *retval;
  if (IN_MALLOC_WRAPPER) {
    retval = calloc(num, size);
  } else {
    retval = fred_calloc(num, size);
  }

  INSTALL_TRAMPOLINE(calloc_trampoline_info);
  return retval;
}

static void *realloc_trampoline(void *ptr, size_t size)
{
  UNINSTALL_TRAMPOLINE(realloc_trampoline_info);

  void *retval;
  if (IN_MALLOC_WRAPPER) {
    retval = realloc(ptr, size);
  } else {
    retval = fred_realloc(ptr, size);
  }

  INSTALL_TRAMPOLINE(realloc_trampoline_info);
  return retval;
}

static void free_trampoline(void *ptr)
{
  UNINSTALL_TRAMPOLINE(free_trampoline_info);

  if (IN_MALLOC_WRAPPER) {
    free(ptr);
  } else {
    fred_free(ptr);
  }

  INSTALL_TRAMPOLINE(free_trampoline_info);
  return;
}

/*
static int posix_memalign_trampoline(void **memptr, size_t alignment, size_t size)
{
  UNINSTALL_TRAMPOLINE(posix_memalign_trampoline_info);

  int retval;
  if (IN_MALLOC_WRAPPER) {
    retval = posix_memalign(memptr, alignment, size);
  } else {
    retval = fred_posix_memalign(memptr, alignment, size);
  }

  INSTALL_TRAMPOLINE(free_trampoline_info);
  return retval;
}
*/


/* Any trampolines which should be installed are done so via this function.
   Called from DmtcpWorker constructor. */
void fred_setup_trampolines()
{
  dmtcp_setup_trampoline("mmap", (void*) &mmap_trampoline,
                         &mmap_trampoline_info);
}

void fred_setup_malloc_family_trampolines()
{
  dmtcp_setup_trampoline_at_addr((void*) &malloc, (void*) &malloc_trampoline,
                                 &malloc_trampoline_info);
  dmtcp_setup_trampoline_at_addr((void*) &calloc, (void*) &calloc_trampoline,
                                 &calloc_trampoline_info);
  dmtcp_setup_trampoline_at_addr((void*) &realloc, (void*) &realloc_trampoline,
                                 &realloc_trampoline_info);
  dmtcp_setup_trampoline_at_addr((void*) &free, (void*) &free_trampoline,
                                 &free_trampoline_info);
  dmtcp_setup_trampoline_at_addr((void*) &memalign, (void*) &memalign_trampoline,
                                 &memalign_trampoline_info);
 // dmtcp_setup_trampoline_at_addr((void*) &posix_memalign, (void*) &posix_memalign_trampoline, //                       &posix_memalign_trampoline_info);
}

void fred_uninstall_malloc_family_trampolines()
{
  UNINSTALL_TRAMPOLINE(calloc_trampoline_info);
  UNINSTALL_TRAMPOLINE(malloc_trampoline_info);
  UNINSTALL_TRAMPOLINE(realloc_trampoline_info);
  UNINSTALL_TRAMPOLINE(free_trampoline_info);
  UNINSTALL_TRAMPOLINE(memalign_trampoline_info);
  //UNINSTALL_TRAMPOLINE(posix_memalign_trampoline_info);
}
