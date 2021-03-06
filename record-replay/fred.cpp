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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/version.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <dlfcn.h>

#include "constants.h"
#include "fred_wrappers.h"
#include "dmtcpplugin.h"
#include "jassert.h"
#include "jfilesystem.h"

#include "synchronizationlogging.h"
#include "log.h"
#include "threadinfo.h"

static inline void memfence() {  asm volatile ("mfence" ::: "memory"); }
void fred_setup_trampolines();

extern "C"
int fred_record_replay_enabled() {
  return 1;
}

static int sync_mode_pre_ckpt = SYNC_NOOP;

static void pthread_atfork_child()
{
  set_sync_mode(SYNC_NOOP);
  log_all_allocs = 0;

  global_log.destroy(SYNC_RECORD);
}


static void recordReplayInit()
{
  // As of rev. 816, this line caused DMTCP with standard ./configure
  //   (no command line flags) to segfault.
  // To see bug, do:  gdb --args bin/dmtcp_checkpoint ls
  // NOTe: This comment may not be true anymore.
  fred_setup_trampolines();

  dmtcp::ThreadInfo::init();
  dmtcp::ThreadInfo::initThread();

  /* Other initialization for sync log/replay specific to this process. */
  initializeLogNames();
  if (getenv(ENV_VAR_LOG_REPLAY) == NULL) {
    /* If it is NULL, this is the very first exec. We unset => set to 0
       (meaning no logging, no replay) */
    // FIXME: setenv is known to cause issues when interacting with bash.
    setenv(ENV_VAR_LOG_REPLAY, "0", 1);
  }
  sync_logging_branch = atoi(getenv(ENV_VAR_LOG_REPLAY));
  /* Synchronize this constructor, if this is not the very first exec. */
  log_entry_t my_entry = create_exec_barrier_entry(0, (event_code_t) 0);
  if (SYNC_IS_REPLAY) {
    memfence();
    waitForExecBarrier();
    getNextLogEntry();
  } else if (SYNC_IS_RECORD) {
    addNextLogEntry(my_entry);
  }

  /* Currently, the processes, under record/replay, mmap the
   * synchronization-log file with shared mapping. During record/replay, any
   * child process created through fork() has access to this log and will
   * modify it while executing some system call that is being logged. We do
   * handle the fork() process by dmtcp_process_event() but that is too late.
   * glibc:fork() will call the functions registered with pthread_atfork() even
   * before the glibc:fork() returns. Thus it is necessary to register our own
   * handle which would disable logging for the child process.
   * This whole scheme works fine when we do not wish to record/replay events
   * within the child process.
   */
  pthread_atfork(NULL, NULL, pthread_atfork_child);

  /* setlocale(LC_ALL, "") will cause the process to mmap all locale related
   * files at once into the process memory. We need to do this because any call
   * to setlocale(LC_XXX, ...) tries to open() the corresponding locale file
   * followed by mmap()'ing it into process memory if not already present. This
   * causes problems when we are in the REPLAY mode. We won't perform the
   * _real_open and thus the mmap() would fail due to bad fd.
   * By calling setlocale(LC_ALL, ...) we avoid all this.
   */
  setlocale(LC_ALL, "");
  char *login_name = getlogin();
  JASSERT(login_name != NULL);

  /* asctime() causes the process to mmap()
   * /usr/libXX/gconv/gconv-modules.cache into memory. Thus any later calls to
   * asctime won't result in the mmap.
   */
  time_t t = time(NULL);
  JASSERT(asctime(localtime(&t)) != NULL);

  JTRACE ( "Record/replay finished initializing." );
}

/* This code used to be called from preCheckpoint hooks. However, in order to
 * modularize record/replay code, we want this to be separate from any hooks.
 * As a result, this code has moved later in the code where we are processing
 * during the POST_SUSPEND state.
 * This move has to make sure that the events that can happen between
 * preCheckpointHook() and dmtcp_process_event(DMTCP_EVENT_POST_SUSPEND) do not
 * cause any memory allocations/deallocations or any other calls that could
 * result in a synchronization event that should otherwise be logged.
 */
void fred_post_suspend ()
{
  JASSERT(sync_mode_pre_ckpt == SYNC_NOOP);
  sync_mode_pre_ckpt = get_sync_mode();
  if (sync_mode_pre_ckpt == SYNC_NOOP) {
    sync_mode_pre_ckpt = SYNC_RECORD;
  }

  set_sync_mode(SYNC_NOOP);
  log_all_allocs = 0;

  global_log.destroy(sync_mode_pre_ckpt);
  close_read_log();

  dmtcp::ThreadInfo::postSuspend();
}

void fred_post_checkpoint_resume()
{
  initSyncAddresses();
  set_sync_mode(sync_mode_pre_ckpt);
  sync_mode_pre_ckpt = SYNC_NOOP;
  initLogsForRecordReplay();
  dmtcp::ThreadInfo::postCkptResume();
  log_all_allocs = 1;
}

void fred_post_restart_resume()
{
  initSyncAddresses();
  set_sync_mode(SYNC_REPLAY);
  sync_mode_pre_ckpt = SYNC_NOOP;
  initLogsForRecordReplay();
  if (global_log.isEndOfLog()) {
    // If no log entries, go back to RECORD.
    set_sync_mode(SYNC_RECORD);
  } else {
    dmtcp::ThreadInfo::postRestartResume();
  }
  log_all_allocs = 1;
}

void fred_reset_on_fork()
{
  dmtcp::ThreadInfo::resetOnFork();
  // Perform other initialization for sync log/replay specific to this process.
  initSyncAddresses();
  initializeLogNames();
}

static void fred_process_thread_start()
{
  if (my_clone_id == -1) {
    dmtcp::ThreadInfo::initThread();
  }
}

EXTERNC void dmtcp_process_event(DmtcpEvent_t event, DmtcpEventData_t *data)
{
  switch (event) {
    case DMTCP_EVENT_INIT:
      recordReplayInit();
      break;
    case DMTCP_EVENT_RESET_ON_FORK:
      fred_reset_on_fork();
      break;
    case DMTCP_EVENT_SUSPENDED:
      fred_post_suspend();
      break;
    case DMTCP_EVENT_RESUME:
      if (data->resumeInfo.isRestart) {
        fred_post_restart_resume();
      } else {
        fred_post_checkpoint_resume();
      }
      break;
    case DMTCP_EVENT_THREAD_START:
      fred_process_thread_start();
      break;

    case DMTCP_EVENT_PTHREAD_RETURN:
    case DMTCP_EVENT_PTHREAD_EXIT:
      dmtcp::ThreadInfo::reapThisThread();
      break;
//    case DMTCP_EVENT_ATFORK_CHILD:
//      pthread_atfork_child();
//      break;
    default:
      break;
  }

  DMTCP_CALL_NEXT_PROCESS_DMTCP_EVENT(event, data);
  return;
}


#if 1

//FIXME: Do we need these definitions?
int __real_dmtcp_userSynchronizedEvent()
{
  userSynchronizedEvent();
  return 1;
}
EXTERNC int _real_dmtcp_userSynchronizedEventBegin()
{
  userSynchronizedEventBegin();
  return 1;
}
EXTERNC int _real_dmtcp_userSynchronizedEventEnd()
{
  userSynchronizedEventEnd();
  return 1;
}

EXTERNC int dmtcp_userSynchronizedEvent()
{
  return __real_dmtcp_userSynchronizedEvent();
}
EXTERNC int dmtcp_userSynchronizedEventBegin()
{
  _real_dmtcp_userSynchronizedEventBegin();
  return 1;
}
EXTERNC int dmtcp_userSynchronizedEventEnd()
{
  _real_dmtcp_userSynchronizedEventEnd();
  return 1;
}

//These dummy trampolines support static linking of user code to libdmtcpaware.a
//See dmtcpaware.c .
//FIXME: Are these needed anymore?
EXTERNC int __dyn_dmtcp_userSynchronizedEvent()
{
  return __real_dmtcp_userSynchronizedEvent();
}

EXTERNC int __dyn_dmtcp_userSynchronizedEventBegin()
{
  return dmtcp_userSynchronizedEventBegin();
}

EXTERNC int __dyn_dmtcp_userSynchronizedEventEnd()
{
  return dmtcp_userSynchronizedEventEnd();
}

int fred_wrappers_initializing = 0;

extern "C" void prepareFredWrappers() {
  fred_wrappers_initializing = 1;
  initialize_wrappers();
  //dmtcp_process_event(DMTCP_EVENT_INIT_WRAPPERS, NULL);
  fred_wrappers_initializing = 0;
}
#endif
