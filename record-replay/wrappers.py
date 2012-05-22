###############################################################################
# Copyright (C) 2009, 2010, 2011, 2012 by Kapil Arya, Gene Cooperman,         #
#                                        Tyler Denniston, and Ana-Maria Visan #
# {kapil,gene,tyler,amvisan}@ccs.neu.edu                                      #
#                                                                             #
# This file is part of FReD.                                                  #
#                                                                             #
# FReD is free software: you can redistribute it and/or modify                #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# FReD is distributed in the hope that it will be useful,                     #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with FReD.  If not, see <http://www.gnu.org/licenses/>.               #
###############################################################################

import pdb
import re
import string

# Format for each wrapper tuple:
# wrapper-tuple := ('<type>', '<name>', <argument-list> [, <opt-wrapper-info>]*)
# argument-list := \[<argument-tuple>*\]
# argument-tuple := ('<type>', '<name>' [,<argument-flag>]*)
# argument-flag := '__save_retval' | '__no_save'
# opt-wrapper-info := ('opt', <optional-flags>) | ('extra', <extra-fields-for-struct>)
# optional-flags := 'decl_data_offset' | 'decl_retval'
# extra-fields-for-struct := '<type> <name>'
#
# Meaning of flags:
#  '__save_retval' : decl a ret_XXX field which saves the return value of this arg
#  '__no_save' : do not include this arg in log entry struct
#  'decl_data_offset' : add a 'off_t data_offset' field to the log entry struct
#  'decl_retval' : add a '<ret-type> <name__retval' field to the log entry struct
#

miscWrappers = [
  ('void', 'empty', []),
  ('int', 'accept', [('int', 'sockfd'),
                     ('struct sockaddr*', 'addr', '__save_retval'),
                     ('socklen_t*', 'addrlen', '__save_retval')]),
  ('int', 'accept4', [('int', 'sockfd'),
                      ('struct sockaddr*', 'addr', '__save_retval'),
                      ('socklen_t*', 'addrlen', '__save_retval'),
                      ('int', 'flags')]),
  ('int', 'access', [('const char*', 'pathname'),
                     ('int', 'mode')]),
  ('int', 'bind', [('int', 'sockfd'),
                   ('const struct sockaddr*', 'my_addr'),
                   ('socklen_t', 'addrlen')]),
  ('void*', 'calloc', [('size_t', 'nmemb'),
                       ('size_t', 'size')]),
  ('int', 'chmod', [('const char*', 'path'),
                    ('mode_t', 'mode')]),
  ('int', 'chown', [('const char*', 'path'),
                    ('uid_t', 'owner'),
                    ('gid_t', 'group')]),
  ('int', 'close', [('int', 'fd')]),
  ('int', 'connect', [('int', 'sockfd'),
                      ('const struct sockaddr*', 'serv_addr'),
                      ('socklen_t', 'addrlen')]),
  ('int', 'dup', [('int', 'oldfd')]),
  ('int', 'dup2', [('int', 'oldfd'),
                   ('int', 'newfd')]),
  ('int', 'dup3', [('int', 'oldfd'),
                   ('int', 'newfd'),
                   ('int', 'flags')]),
  # FIXME: fcntl needs more values (use readlog?)
  ('int', 'fcntl', [('int', 'fd'),
                    ('int', 'cmd'),
                    ('void*', 'arg')],
                   ('extra', 'struct flock ret_flock')),
  ('int', 'fchdir', [('int', 'fd')]),
  ('int', 'fdatasync', [('int', 'fd')]),
  ('char*', 'getcwd', [('char*', 'buf'),
                       ('size_t', 'size')],
                      ('opt', 'decl_data_offset')),
  ('int', 'gettimeofday', [('struct timeval*', 'tv', '__save_retval'),
                           ('struct timezone*', 'tz', '__save_retval')],
                          ('opt', 'decl_retval')),
  ('int', 'getpeername', [('int', 'sockfd'),
                          ('struct sockaddr*', 'addr', '__save_retval'),
                          ('socklen_t*', 'addrlen', '__save_retval')]),
  ('int', 'getsockname', [('int', 'sockfd'),
                          ('struct sockaddr*', 'addr', '__save_retval'),
                          ('socklen_t*', 'addrlen', '__save_retval')]),
  ('int', 'link', [('const char*', 'oldpath'),
                   ('const char*', 'newpath')]),
  ('int', 'symlink', [('const char*', 'oldpath'),
                      ('const char*', 'newpath')]),
  ('int', 'listen', [('int', 'sockfd'),
                     ('int', 'backlog')]),
  ('struct tm*', 'localtime_r', [('const time_t*', 'timep'),
                                 ('struct tm*', 'result', '__save_retval')]),
  ('int', 'utime', [('const char*', 'filename'),
                    ('const struct utimbuf*', 'times')]),
  ('int', 'utimes', [('const char*', 'filename'),
                     ('const struct timeval*', 'times')]),
  ('int', 'lutimes', [('const char*', 'filename'),
                      ('const struct timeval*', 'tv')]),
  ('int', 'futimes', [('int', 'fd'),
                      ('const struct timeval*', 'tv')]),
  ('int', 'clock_getres', [('clockid_t', 'clk_id'),
                           ('struct timespec*', 'res', '__save_retval')]),
  ('int', 'clock_gettime', [('clockid_t', 'clk_id'),
                            ('struct timespec*', 'tp', '__save_retval')]),
  ('int', 'clock_settime', [('clockid_t', 'clk_id'),
                            ('const struct timespec*', 'tp')]),
  ('off_t', 'lseek', [('int', 'fd'),
                      ('off_t', 'offset'),
                      ('int', 'whence')]),
  ('off64_t', 'lseek64', [('int', 'fd'),
                          ('off64_t', 'offset'),
                          ('int', 'whence')]),
  ('loff_t', 'llseek', [('int', 'fd'),
                        ('loff_t', 'offset'),
                        ('int', 'whence')]),
  ('void*', 'malloc', [('size_t', 'size')]),

  ('void', 'free', [('void*', 'ptr')]),

  ('int', 'mkdir', [('const char*', 'pathname'),
                    ('mode_t', 'mode')]),
  ('int', 'mkstemp', [('char*', 'temp')]),
  ('void*', 'mmap', [('void*', 'addr'),
                     ('size_t', 'length'),
                     ('int', 'prot'),
                     ('int', 'flags'),
                     ('int', 'fd'),
                     ('off_t', 'offset')],
                    ('opt', 'decl_data_offset')),
  ('void*', 'mmap64', [('void*', 'addr'),
                       ('size_t', 'length'),
                       ('int', 'prot'),
                       ('int', 'flags'),
                       ('int', 'fd'),
                       ('off64_t', 'offset')],
                      ('opt', 'decl_data_offset')),
  ('int', 'munmap', [('void*', 'addr'),
                     ('size_t', 'length')]),
  ('void*', 'mremap', [('void*', 'old_address'),
                       ('size_t', 'old_size'),
                       ('size_t', 'new_size'),
                       ('int', 'flags'),
                       ('void*', 'new_address')]),
  ('int', 'open', [('const char*', 'pathname'),
                   ('int', 'flags'),
                   ('mode_t', 'mode')]),
  ('int', 'open64', [('const char*', 'pathname'),
                     ('int', 'flags'),
                     ('mode_t', 'mode')]),
  ('int', 'openat', [('int', 'dirfd'),
                     ('const char*', 'pathname'),
                     ('int', 'flags')]),
  ('ssize_t', 'pread', [('int', 'fd'),
                        ('void*', 'buf'),
                        ('size_t', 'count'),
                        ('off_t', 'offset')],
                       ('opt', 'decl_data_offset')),
  ('ssize_t', 'preadv', [('int', 'fd'),
                         ('const struct iovec*', 'iov'),
                         ('int', 'iovcnt'),
                         ('off_t', 'offset')],
                        ('opt', 'decl_data_offset')),
  ('ssize_t', 'pwrite', [('int', 'fd'),
                         ('const void*', 'buf'),
                         ('size_t', 'count'),
                         ('off_t', 'offset')]),
  ('ssize_t', 'pwritev', [('int', 'fd'),
                          ('const struct iovec*', 'iov'),
                          ('int', 'iovcnt'),
                          ('off_t', 'offset')]),
  ('int', 'pthread_rwlock_unlock', [('pthread_rwlock_t*', 'rwlock', '__save_retval')]),
  ('int', 'pthread_rwlock_rdlock', [('pthread_rwlock_t*', 'rwlock', '__save_retval')]),
  ('int', 'pthread_rwlock_wrlock', [('pthread_rwlock_t*', 'rwlock', '__save_retval')]),
  ('int', 'pthread_create', [('pthread_t*', 'thread'),
                             ('const pthread_attr_t*', 'attr'),
                             ('pthread_start_routine_t', 'start_routine'),
                             ('void*', 'arg')],
                            ('extra', 'void *stack_addr'),
                            ('extra', 'size_t stack_size')),
  ('int', 'pthread_detach', [('pthread_t', 'thread')]),
  ('void', 'pthread_exit', [('void*', 'value_ptr')]),
  ('int', 'pthread_join', [('pthread_t', 'thread'),
                           ('void**', 'value_ptr')]),
  ('int', 'pthread_kill', [('pthread_t', 'thread'),
                           ('int', 'sig')]),
  ('int', 'pthread_mutex_lock', [('pthread_mutex_t*', 'mutex', '__save_retval')]),
  ('int', 'pthread_mutex_trylock', [('pthread_mutex_t*', 'mutex', '__save_retval')]),
  ('int', 'pthread_mutex_unlock', [('pthread_mutex_t*', 'mutex', '__save_retval')]),
  ('int', 'rand', []),
  ('ssize_t', 'read', [('int', 'fd'),
                       ('void*', 'buf'),
                       ('size_t', 'count')],
                      ('opt', 'decl_data_offset')),
  ('ssize_t', 'readv', [('int', 'fd'),
                        ('const struct iovec*', 'iov'),
                        ('int', 'iovcnt')],
                       ('opt', 'decl_data_offset')),
  ('ssize_t', 'readlink', [('const char*', 'path'),
                           ('char*', 'buf'),
                           ('size_t', 'bufsiz')],
                          ('opt', 'decl_data_offset')),
  ('char*', 'realpath', [('const char*', 'path'),
                         ('char*', 'resolved_path')],
                        ('opt', 'decl_data_offset'),
                        ('extra', 'size_t len')),
  ('void*', 'realloc', [('void*', 'ptr'),
                        ('size_t', 'size')]),
  ('int', 'rename', [('const char*', 'oldpath'),
                     ('const char*', 'newpath')]),
  ('int', 'rmdir', [('const char*', 'pathname')]),
  ('int', 'select', [('int', 'nfds'),
                     ('fd_set*', 'readfds', '__save_retval'),
                     ('fd_set*', 'writefds', '__save_retval'),
                     ('fd_set*', 'exceptfds'),
                     ('struct timeval*', 'timeout')]),
  ('int', 'ppoll', [('struct pollfd*', 'fds'),
                    ('nfds_t', 'nfds'),
                    ('const struct timespec*', 'timeout_ts'),
                    ('const sigset_t*', 'sigmask')],
                   ('opt', 'decl_data_offset')),
  ('int', 'setsockopt', [('int', 's'),
                         ('int', 'level'),
                         ('int', 'optname'),
                         ('const void*', 'optval'),
                         ('socklen_t', 'optlen')]),
  ('int', 'getsockopt', [('int', 's'),
                         ('int', 'level'),
                         ('int', 'optname'),
                         ('void*', 'optval'),
                         ('socklen_t*', 'optlen', '__save_retval')],
                        ('opt', 'decl_data_offset')),
  ('int', 'ioctl', [('int', 'd'),
                    ('int', 'request'),
                    ('void*', 'arg')],
                   ('opt', 'decl_data_offset'),
                   ('extra', 'struct winsize win_val'),
                   ('extra', 'struct ifconf ifconf_val'),
                   ('extra', 'int fionread_val')),
  ('int', 'sigwait', [('const sigset_t*', 'set'),
                      ('int*', 'sig', '__save_retval')]),
  ('void', 'srand', [('unsigned int', 'seed')]),
  ('int', 'socket', [('int', 'domain'),
                     ('int', 'type'),
                     ('int', 'protocol')]),
  # FIXME: ret_sv??
  ('int', 'socketpair', [('int', 'd'),
                         ('int', 'type'),
                         ('int', 'protocol'),
                         ('int*', 'sv')],
                        ('extra', 'int ret_sv[2]')),
  ('time_t', 'time', [('time_t*', 'tloc')], ('opt', 'decl_retval')),
  ('int', 'truncate', [('const char*', 'path'),
                       ('off_t', 'length')]),
  ('int', 'ftruncate', [('int', 'fd'),
                        ('off_t', 'length')]),
  ('int', 'truncate64', [('const char*', 'path'),
                         ('off64_t', 'length')]),
  ('int', 'ftruncate64', [('int', 'fd'),
                          ('off64_t', 'length')]),
  ('int', 'unlink', [('const char*', 'pathname')]),
  ('ssize_t', 'write', [('int', 'fd'),
                        ('const void*', 'buf'),
                        ('size_t', 'count')]),
  ('ssize_t', 'writev', [('int', 'fd'),
                         ('const struct iovec*', 'iov'),
                         ('int', 'iovcnt')]),
  ('int', 'epoll_create', [('int', 'size')]),
  ('int', 'epoll_create1', [('int', 'flags')]),
  ('int', 'epoll_ctl', [('int', 'epfd'),
                        ('int', 'op'),
                        ('int', 'fd'),
                        ('struct epoll_event*', 'ep')]),
  ('int', 'epoll_wait', [('int', 'epfd'),
                         ('struct epoll_event*', 'events'),
                         ('int', 'maxevents'),
                         ('int', 'timeout')],
                        ('opt', 'decl_data_offset')),
  ('int', 'getpwnam_r', [('const char*', 'name'),
                         ('struct passwd*', 'pwd', '__save_retval'),
                         ('char*', 'buf'),
                         ('size_t', 'buflen'),
                         ('struct passwd**', 'result', '__save_retval')],
                        ('opt', 'decl_data_offset')),
  ('int', 'getpwuid_r', [('uid_t', 'uid'),
                         ('struct passwd*', 'pwd', '__save_retval'),
                         ('char*', 'buf'),
                         ('size_t', 'buflen'),
                         ('struct passwd**', 'result', '__save_retval')],
                        ('opt', 'decl_data_offset')),
  ('int', 'getgrnam_r', [('const char*', 'name'),
                         ('struct group*', 'grp', '__save_retval'),
                         ('char*', 'buf'),
                         ('size_t', 'buflen'),
                         ('struct group**', 'result', '__save_retval')],
                        ('opt', 'decl_data_offset')),
  ('int', 'getgrgid_r', [('gid_t', 'gid'),
                         ('struct group*', 'grp', '__save_retval'),
                         ('char*', 'buf'),
                         ('size_t', 'buflen'),
                         ('struct group**', 'result', '__save_retval')],
                        ('opt', 'decl_data_offset')),
  ('int', 'getaddrinfo', [('const char*', 'node'),
                          ('const char*', 'service'),
                          ('const struct addrinfo*', 'hints'),
                          ('struct addrinfo**', 'res', '__save_retval')],
                        ('opt', 'decl_data_offset'),
                        ('extra', 'int num_results')),
  ('void', 'freeaddrinfo', [('struct addrinfo*', 'res')]),
  ('int', 'getnameinfo', [('const struct sockaddr*', 'sa'),
                          ('socklen_t', 'salen'),
                          ('char*', 'host'),
                          ('size_t', 'hostlen'),
                          ('char*', 'serv'),
                          ('size_t', 'servlen'),
                          ('int', 'flags')],
                        ('opt', 'decl_data_offset'),
                        ('extra', 'char ret_host[NI_MAXHOST]'),
                        ('extra', 'char ret_serv[NI_MAXSERV]')),
  ('ssize_t', 'sendto', [('int', 'sockfd'),
                         ('const void*', 'buf'),
                         ('size_t', 'len'),
                         ('int', 'flags'),
                         ('const struct sockaddr*', 'dest_addr'),
                         ('socklen_t', 'addrlen')]),
  ('ssize_t', 'sendmsg', [('int', 'sockfd'),
                          ('const struct msghdr*', 'msg'),
                          ('int', 'flags')]),
  ('ssize_t', 'recvfrom', [('int', 'sockfd'),
                           ('void*', 'buf'),
                           ('size_t', 'len'),
                           ('int', 'flags'),
                           ('struct sockaddr*', 'src_addr', '__save_retval'),
                           ('socklen_t*', 'addrlen', '__save_retval')],
                          ('opt', 'decl_data_offset')),
  ('ssize_t', 'recvmsg', [('int', 'sockfd'),
                          ('struct msghdr*', 'msg', '__save_retval'),
                          ('int', 'flags')],
                         ('opt', 'decl_data_offset'),
                         ('extra', 'off_t control_buf_offset')),
  ('int', 'waitid', [('idtype_t', 'idtype'),
                     ('id_t', 'id'),
                     ('siginfo_t*', 'infop', '__save_retval'),
                     ('int', 'options')]),
  ('pid_t', 'wait4', [('pid_t', 'pid'),
                      ('__WAIT_STATUS', 'status', '__save_retval'),
                      ('int', 'options'),
                      ('struct rusage*', 'rusage', '__save_retval')]),
  ('int', 'sigaction', [('int', 'signum'),
                        ('const struct sigaction*', 'act'),
                        ('struct sigaction*', 'oldact')]),
  ('sighandler_t', 'signal', [('int', 'signum'),
                              ('sighandler_t', 'handler')]),
  ('sighandler_t', 'sigset', [('int', 'sig'),
                              ('sighandler_t', 'disp')]),
]

fstreamWrappers = [

  ('FILE*', 'fopen', [('const char*', 'path'),
                      ('const char*', 'mode')],
                     ('opt', 'decl_retval')),

  ('FILE*', 'fopen64', [('const char*', 'path'),
                        ('const char*', 'mode')],
                       ('opt', 'decl_retval')),

  ('FILE*', 'freopen', [('const char*', 'path'),
                        ('const char*', 'mode'),
                        ('FILE*', 'stream')],
                       ('opt', 'decl_retval')),
  ('int', 'fclose', [('FILE*', 'fp')]),

  ('FILE*', 'fdopen', [('int', 'fd'),
                       ('const char*', 'mode')],
                      ('opt', 'decl_retval')),

  ('char*', 'fgets', [('char*', 's'),
                      ('int', 'size'),
                      ('FILE*', 'stream')],
                     ('opt', 'decl_data_offset')),

  ('int', 'ferror', [('FILE*', 'stream')]),

  ('int', 'feof', [('FILE*', 'stream')]),

  ('int', 'fileno', [('FILE*', 'stream')]),

  ('int', 'fflush', [('FILE*', 'stream')]),

  ('int', 'setvbuf', [('FILE*', 'stream'),
                      ('char*', 'buf'),
                      ('int', 'mode'),
                      ('size_t', 'size')]),

  ('int', 'fseek', [('FILE*', 'stream'),
                    ('long', 'offset'),
                    ('int', 'whence')]),

  ('int', 'fputs', [('const char*', 's'),
                    ('FILE*', 'stream')]),

  ('int', 'fputc', [('int', 'c'),
                    ('FILE*', 'stream')]),

  ('int', 'fsync', [('int', 'fd')]),

  ('long', 'ftell', [('FILE*', 'stream')]),

  ('size_t', 'fwrite', [('const void*', 'ptr'),
                        ('size_t', 'size'),
                        ('size_t', 'nmemb'),
                        ('FILE*', 'stream')]),

  ('size_t', 'fread', [('void*', 'ptr'),
                       ('size_t', 'size'),
                       ('size_t', 'nmemb'),
                       ('FILE*', 'stream')],
                      ('opt', 'decl_data_offset')),

  ('int', 'getc', [('FILE*', 'stream')]),

  ('int', 'fgetc', [('FILE*', 'stream')]),

  ('int', 'ungetc', [('int', 'c'),
                     ('FILE*', 'stream')]),

  ('ssize_t', 'getline', [('char**', 'lineptr', '__save_retval'),
                          ('size_t*', 'n', '__save_retval'),
                          ('FILE*', 'stream')],
                         ('opt', 'decl_data_offset')),

  ('ssize_t', 'getdelim', [('char**', 'lineptr', '__save_retval'),
                           ('size_t*', 'n', '__save_retval'),
                           ('int', 'delim'),
                           ('FILE*', 'stream')],
                          ('opt', 'decl_data_offset')),

  ('int', 'putc', [('int', 'c'),
                   ('FILE*', 'stream')]),

  ('void', 'rewind', [('FILE*', 'stream')]),

  ('FILE*', 'tmpfile', [], ('opt', 'decl_retval')),

  ('void', 'flockfile', [('FILE*', 'filehandle')]),

  ('int', 'ftrylockfile', [('FILE*', 'filehandle')]),

  ('void', 'funlockfile', [('FILE*', 'filehandle')]),

  ('int', 'closedir', [('DIR*', 'dirp')]),

  ('DIR*', 'opendir', [('const char*', 'name')]),

  ('DIR*', 'fdopendir', [('int', 'fd')]),

  ('struct dirent*', 'readdir', [('DIR*', 'dirp')], ('opt', 'decl_retval')),

  ('int', 'readdir_r', [('DIR*', 'dirp'),
                        ('struct dirent*', 'entry', '__save_retval'),
                        ('struct dirent**', 'result', '__save_retval')]),

]

#REACH_RECORD_REPLAY_WRAPPER_2('MACRO')]),
pthreadCondWrappers = [
  ('int', 'pthread_cond_broadcast', [('pthread_cond_t*', 'cond', '__save_retval')]),
  ('int', 'pthread_cond_signal', [('pthread_cond_t*', 'cond', '__save_retval')]),
  ('int', 'pthread_cond_wait', [('pthread_cond_t*', 'cond', '__save_retval'),
                                ('pthread_mutex_t*', 'mutex', '__save_retval')]),
  ('int', 'pthread_cond_timedwait', [('pthread_cond_t*', 'cond', '__save_retval'),
                                     ('pthread_mutex_t*', 'mutex', '__save_retval'),
                                     ('const struct timespec*', 'abstime')]),
  ('int', 'pthread_cond_destroy', [('pthread_cond_t*', 'cond', '__save_retval')]),
]


#REACH_RECORD_REPLAY_WRAPPER_3('MACRO')]),
xstatWrappers = [
  ('int', 'fxstat', [('int', 'vers'),
                     ('int', 'fd'),
                     ('struct stat*', 'buf', '__save_retval')]),
  ('int', 'fxstat64', [('int', 'vers'),
                       ('int', 'fd'),
                       ('struct stat64*', 'buf', '__save_retval')]),
  ('int', 'lxstat', [('int', 'vers'),
                     ('const char*', 'path'),
                     ('struct stat*', 'buf', '__save_retval')]),
  ('int', 'lxstat64', [('int', 'vers'),
                       ('const char*', 'path'),
                       ('struct stat64*', 'buf', '__save_retval')]),
  ('int', 'xstat', [('int', 'vers'),
                    ('const char*', 'path'),
                    ('struct stat*', 'buf', '__save_retval')]),
  ('int', 'xstat64', [('int', 'vers'),
                      ('const char*', 'path'),
                      ('struct stat64*', 'buf', '__save_retval')]),
  ('void*', 'libc_memalign', [('size_t', 'boundary'),
                              ('size_t', 'size')]),
]


#REACH_RECORD_REPLAY_WRAPPER_4('MACRO')]),
printfScanfWrappers = [
  ('int', 'fprintf', [('FILE*', 'stream'),
                      ('const char*', 'format'),
                      ('va_list', 'ap', '__no_save')]),
  ('int', 'fscanf', [('FILE*', 'stream'),
                     ('const char*', 'format'),
                     ('va_list', 'ap', '__no_save')],
                    ('opt', 'decl_data_offset'),
                    ('extra', 'int bytes')),
]

noSyscallWrappers = [
  #REACH_RECORD_REPLAY_WRAPPER_5('MACRO')]),
  ('void', 'exec_barrier', []),
  ('void', 'signal_handler', [('int', 'sig'),
                              ('siginfo_t*', 'info'),
                              ('void*', 'data')]),
  ('void', 'user', []),
]

#REACH_NON_RECORD_REPLAY_WRAPPER('MACRO')]),
syscallWrapper = [
  ('long int', 'syscall', [('int', 'num'),
                           ('void*', 'a1'),
                           ('void*', 'a2'),
                           ('void*', 'a3'),
                           ('void*', 'a4'),
                           ('void*', 'a5'),
                           ('void*', 'a6'),
                           ('void*', 'a7')]),
]

wrapperGroups = [miscWrappers,
                 fstreamWrappers,
                 pthreadCondWrappers,
                 xstatWrappers,
                 printfScanfWrappers,
                 noSyscallWrappers,
                 syscallWrapper
                ]

copyrightHdr = """\
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

/* This file is auto-generated. Please modify wrappers.py and re-execute it
 * to make any changes to this file.
 */

"""

def get_wrapper_enum(wrapper):
    return wrapper[1] + "_event"

def get_wrapper_enum_list():
    enumList=[]
    for wrapperGroup in wrapperGroups:
        enumList += map(get_wrapper_enum, wrapperGroup)
    return enumList


def get_arg_decl(a):
    return string.join(a[:2])

def get_arg_signature(wrapper):
    declList = map(get_arg_decl, wrapper[2])
    argSignature = string.join(declList, ', ')
    return argSignature


def get_real_XXX_decl():
    res = []
    for wrapperGroup in wrapperGroups:
        for wrapper in wrapperGroup:
            if wrapper[1] == 'syscall':
                res += ['long int _real_syscall(long int sys_num, ...);']
            else:
                res += ['%s _real_%s(%s);' \
                        % (wrapper[0], wrapper[1], get_arg_signature(wrapper))]
    return res

def get_real_XXX_addrs():
    res = []
    for wrapper in miscWrappers + fstreamWrappers:
        res += ['\t_real_func_addr[%s] = _real_dlsym(RTLD_NEXT, %s);'
                % (get_wrapper_enum(wrapper), wrapper[1])];
    for wrapper in pthreadCondWrappers:
        res += ['\t_real_func_addr[%s] = dlvsym(RTLD_NEXT, %s, "GLIBC_2.3.2");'
                % (get_wrapper_enum(wrapper), wrapper[1])];
    for wrapper in xstatWrappers:
        res += ['\t_real_func_addr[%s] = _real_dlsym(RTLD_NEXT, __%s);'
                % (get_wrapper_enum(wrapper), wrapper[1])];
    return res


enumList = get_wrapper_enum_list() + ['numTotalWrappers']
realDecl = get_real_XXX_decl()
realAddrs = get_real_XXX_addrs()


############################## 
# Generate fred_wrappers.h
############################## 

def create_fred_wrappers_h():
    header = """
#ifndef FRED_WRAPPERS_H
#define FRED_WRAPPERS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <utime.h>
#include <sys/time.h>
#include <net/if.h>
#include <stdarg.h>
#include <asm/ldt.h>
#include <stdio.h>
#include <thread_db.h>
#include <sys/procfs.h>
#include <syslog.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <dirent.h>
#include <unistd.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>

#include "constants.h"
#include "fred_types.h"

#define LIB_PRIVATE __attribute__ ((visibility ("hidden")))

#ifdef __cplusplus
extern "C"
{
#endif

"""

    footer = """

  extern int fred_wrappers_initializing;
  void _dmtcp_setup_trampolines();
  void initialize_wrappers();
  void *_real_dlsym(void *handle, const char *symbol);
  void *get_real_func_addr(event_code_t e, const char *name);
  void *dmtcp_get_libc_dlsym_addr();
  void prepareFredWrappers();

#if __GLIBC_PREREQ(2,5)
# define READLINK_RET_TYPE ssize_t
#else
# define READLINK_RET_TYPE int
#endif

  void *fred_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
  void *fred_mremap(void *old_address, size_t old_size,
                    size_t new_size, int flags, ...);
  int fred_munmap(void *addr, size_t length);

#ifdef __cplusplus
}
#endif

#endif
"""

    enum_str = '  typedef enum {\n    %s\n  } event_code_t;\n\n' \
                               % (string.join(enumList, ',\n    '))

    fd = open('fred_wrappers.h', 'w')
    fd.write(copyrightHdr)
    fd.write(header)
    fd.write(enum_str)
    fd.write('  ')
    fd.write(string.join(realDecl, '\n  '))
    fd.write(footer)
    fd.close()


def create_syscallsreal_helper_c():
    header = """
#include "fred_wrappers.h"
#include "trampolines.h"
#include <dlfcn.h>

void * _real_dlsym ( void *handle, const char *symbol );

static void *_real_func_addr[numTotalWrappers];
static int _wrappers_initialized = 0;

static char wrapper_init_buf[1024];
static trampoline_info_t pthread_getspecific_trampoline_info;
void *_fred_pthread_getspecific(pthread_key_t key)
{
  if (_wrappers_initialized) {
    fprintf(stderr, "DMTCP INTERNAL ERROR\\n\\n");
    abort();
  }
  pthread_setspecific(key, wrapper_init_buf);
  UNINSTALL_TRAMPOLINE(pthread_getspecific_trampoline_info);
  return pthread_getspecific(key);
}

static void _fred_PreparePthreadGetSpecific()
{
  dmtcp_setup_trampoline_by_addr(&pthread_getspecific,
                                 (void*) &_fred_pthread_getspecific,
                                 &pthread_getspecific_trampoline_info);
}

"""
    
    footer = """
LIB_PRIVATE
void initialize_wrappers()
{
  if (!_wrappers_initialized) {
    _fred_PreparePthreadGetSpecific();
    fred_get_libc_func_addr();
    _wrappers_initialized = 1;
  }
}

LIB_PRIVATE
void *get_real_func_addr(event_code_t e, const char *name) {
  if (_real_func_addr[e] == NULL) {
    prepareFredWrappers();
  }
  if (_real_func_addr[e] == NULL) {
    fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\\n"
                    "           The symbol wasn't found in current library"
                    " loading sequence.\\n"
                    "    Aborting.\\n", name);
    abort();
  }
  return _real_func_addr[e];
}

LIB_PRIVATE
void *_real_dlsym(void *handle, const char *symbol) {
  typedef void* ( *fncptr ) (void *handle, const char *symbol);
  fncptr dlsym_fptr = NULL;

  if (dlsym_fptr == 0) {
    dlsym_fptr = dmtcp_get_libc_dlsym_addr();
    if (dlsym_fptr == NULL) {
      fprintf(stderr, "DMTCP: Internal Error: Not Reached\\n");
      abort();
    }
  }

  return (*dlsym_fptr) ( handle, symbol );
}

"""

    get_libc_func_addr_start = 'static void fred_get_libc_func_addr() {\n'
    get_libc_func_addr_end = '\n}\n'

    libc_func_addr = []
    for wrapper in miscWrappers + fstreamWrappers + syscallWrapper:
        libc_func_addr += ['_real_func_addr[%s] = _real_dlsym(RTLD_NEXT, "%s");' \
                           % (get_wrapper_enum(wrapper), wrapper[1])]
    for wrapper in pthreadCondWrappers:
        libc_func_addr += ['_real_func_addr[%s] = dlvsym(RTLD_NEXT, "%s", "GLIBC_2.3.2");' \
                           % (get_wrapper_enum(wrapper), wrapper[1])]
    for wrapper in xstatWrappers:
        libc_func_addr += ['_real_func_addr[%s] = _real_dlsym(RTLD_NEXT, "__%s");' \
                           % (get_wrapper_enum(wrapper), wrapper[1])]

    fd = open('syscallsreal_helper.c', 'w')
    fd.write(copyrightHdr)
    fd.write(header)
    fd.write(get_libc_func_addr_start)
    fd.write('  ')
    fd.write(string.join(libc_func_addr, '\n  '))
    fd.write(get_libc_func_addr_end)
    fd.write(footer)
    fd.close()

def get_create_entry_fn(wrapper):
    sign = 'log_entry_t create_%s_entry(' % (wrapper[1])
    slen = len(sign)
    sign += 'clone_id_t clone_id, event_code_t event'
    if len(wrapper[2]) > 0:
        sign += ',\n%s%s' % (' ' * slen, get_arg_signature(wrapper))

    sign += ')'
    body = """
{
  log_entry_t e = EMPTY_LOG_ENTRY;
  setupCommonFields(&e, clone_id, event);
"""
    for arg in wrapper[2]:
        if not '__no_save' in arg:
            body += '  SET_FIELD(e, %s, %s);\n' % (wrapper[1], arg[1])

    body += """\
  return e;
}
"""
    return (sign, body)

def get_turn_check_p_fn(wrapper):
    ret = 'int %s_turn_check(log_entry_t *e1, log_entry_t *e2)\n' % (wrapper[1])
    ret += '{\n  return base_turn_check(e1,e2)'
    for arg in wrapper[2]:
        ret += '\n    && '
        ret += 'ARE_FIELDS_EQUAL_PTR (e1, e2, %s, %s)'  % (wrapper[1], arg[1])
    ret += ';\n}\n'
    return ret

def get_deref_type(t):
    tt = t.rstrip()
    if tt[-1] == '*':
        return tt[:-1]
    return tt

def get_struct_def(wrapper):
    ret = 'typedef struct {\n'
    for arg in wrapper[2]:
        ret += '  %s %s;\n' % (arg[0], arg[1])
        if '__save_retval' in arg:
            ret += '  %s %s;\n' % (get_deref_type(arg[0]), 'ret_' + arg[1])
    for rest in wrapper[3:]:
        if rest[0] == 'opt':
            if rest[1] == 'decl_data_offset':
                ret += '  off_t data_offset;\n'
            if rest[1] == 'decl_retval':
                ret += '  %s %s_retval;\n' % (get_deref_type(wrapper[0]), wrapper[1])
        if rest[0] == 'extra':
            ret += '  %s;\n' % (rest[1])

    ret += '} log_event_%s_t;\n' % (wrapper[1])
    return ret

def create_wrapper_util_h():
    header = """\
#ifndef WRAPPER_UTIL2_H
#define WRAPPER_UTIL2_H

#include "fred_wrappers.h"
#include "wrapper_util.h"

#ifdef __cplusplus
extern "C"
{
#endif
"""
    log_entry_decl = """
typedef struct {
  event_code_t event;
  unsigned char isOptional;
  log_off_t log_offset;
  clone_id_t clone_id;
  int my_errno;
  void* retval;
} log_entry_header_t;

typedef struct {
  // We aren't going to map more than 256 system calls/functions.
  // We can expand it to 4 bytes if needed. However a single byte makes
  // things easier.
  // Shared among all events ("common area"):
  /* IMPORTANT: Adding new fields to the common area requires that you also
   * update the log_event_common_size definition. */
  log_entry_header_t header;

  union log_entry_data edata;
} log_entry_t;
"""
    footer = """

size_t getLogEventSize(const log_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif"""

    log_entry_union_start = 'union log_entry_data {\n  '
    log_entry_union_end = '\n};\n'

    event_size = []
    log_entry_union = []
    struct_def = []
    turn_check_p = []
    create_entry = []
    for wrapperGroup in wrapperGroups:
        for wrapper in wrapperGroup:
            event_size += ['static const int log_event_%s_size = sizeof(log_event_%s_t);' \
                           % (wrapper[1], wrapper[1])]
            log_entry_union += ['log_event_%s_t log_event_%s;' \
                                % (wrapper[1], wrapper[1])]
            turn_check_p += ['int %s_turn_check(log_entry_t *e1, log_entry_t *e2);' \
                             % (wrapper[1])]
            (create_entry_sign, create_entry_body) = get_create_entry_fn(wrapper)
            create_entry += [create_entry_sign + ';']
            struct_def += [get_struct_def(wrapper)]

    fd = open('wrapper_util.h', 'w')
    fd.write(copyrightHdr)
    fd.write(header)

    #fd.write(string.join(event_size, '\n'))
    #fd.write('\n\n')

    fd.write(string.join(struct_def, '\n'))
    fd.write('\n\n')

    fd.write(log_entry_union_start)
    fd.write(string.join(log_entry_union, '\n  '))
    fd.write(log_entry_union_end)

    fd.write('\n\n')
    fd.write(log_entry_decl)
    fd.write('\n\n')

    fd.write(string.join(turn_check_p, '\n'))
    fd.write('\n\n')
    fd.write(string.join(create_entry, '\n'))
    fd.write('\n')


    fd.write(footer)
    fd.close()


def create_wrapper_util_cpp():
    header = """\
#include "wrapper_util2.h"
#include "synchronizationlogging.h"
"""
    footer = ''

    log_event_size_start="""
static size_t log_event_size[numTotalWrappers] = {
"""
    log_event_size_end = """
};

size_t getLogEventSize(const log_entry_t *entry)
{
  return log_event_size[entry->header.event];
}
"""

    setup_common_fields = """
static void setupCommonFields(log_entry_t *e, clone_id_t clone_id, event_code_t event)
{
  SET_COMMON_PTR(e, clone_id);
  SET_COMMON_PTR(e, event);
  // Zero out all other fields:
  // FIXME: Shouldn't we replace the memset with a simpler SET_COMMON_PTR()?
  SET_COMMON_PTR2(e, log_offset, INVALID_LOG_OFFSET);
  memset(&(GET_COMMON_PTR(e, my_errno)), 0, sizeof(GET_COMMON_PTR(e, my_errno)));
  memset(&(GET_COMMON_PTR(e, retval)), 0, sizeof(GET_COMMON_PTR(e, retval)));
}
"""
    base_turn_check = """
static int base_turn_check(log_entry_t *e1, log_entry_t *e2) {
  // Predicate function for a basic check -- event # and clone id.
  return GET_COMMON_PTR(e1,clone_id) == GET_COMMON_PTR(e2,clone_id) &&
         GET_COMMON_PTR(e1,event) == GET_COMMON_PTR(e2,event);
}
"""
    event_size = []
    create_entry_fn = []
    turn_check_p_fn = []
    for wrapperGroup in wrapperGroups:
        for wrapper in wrapperGroup:
            event_size += ['  sizeof(log_event_%s_t),' % (wrapper[1])]
            (create_entry_sign, create_entry_body) = get_create_entry_fn(wrapper)
            create_entry_fn += [create_entry_sign + create_entry_body]
            turn_check_p_fn += [get_turn_check_p_fn(wrapper)]

    fd = open('wrapper_util.cpp', 'w')
    fd.write(copyrightHdr)
    fd.write(header)

    fd.write(log_event_size_start)
    fd.write(string.join(event_size, '\n'))
    fd.write(log_event_size_end)

    fd.write(setup_common_fields + '\n')
    fd.write(string.join(create_entry_fn, '\n'))
    fd.write(base_turn_check + '\n')
    fd.write(string.join(turn_check_p_fn, '\n'))

    fd.write(footer)
    fd.close()


def create_fred_read_log_h():
    header = """\
#include "synchronizationlogging.h"

void print_log_entry_common(int idx, log_entry_t *entry);

"""
    footer = ''

    print_entry_start = 'void printEntry(int idx, log_entry_t *entry)\n{\n'
    print_entry_start += 'switch (entry->header.event) {\n'

    print_entry_end = '  }\n}\n'
    log_event_str = 'static const char *log_event_str[] = {\n'

    print_log_entry = []
    print_entry = []
    for wrapperGroup in wrapperGroups:
        for wrapper in wrapperGroup:
            print_str = 'void print_log_entry_%s' % (wrapper[1])
            print_str += '(int idx, log_entry_t *entry) {\n'
            print_str += '  print_log_entry_common(idx, entry);\n'
            print_str += '  printf("'
            print_arg = ''
            for arg in wrapper[2]:
                print_str += '%s=' % arg[1]
                if not '__no_save' in arg:
                    print_arg += ',\n         GET_FIELD_PTR(entry, %s, %s)' \
                                 % (wrapper[1], arg[1])
                    if arg[1].rstrip()[-1] == '*':
                        print_str += ', %p'
            print_str += '\\n"' + print_arg + ');\n}\n'
            print_log_entry += [print_str]

            print_entry += ['    case %s: print_log_entry_%s(idx, entry); break;\n' \
                            % (get_wrapper_enum(wrapper), wrapper[1])]

            log_event_str += '  "%s",\n' % (wrapper[1])

    fd = open('fred_read_log.h', 'w')
    fd.write(copyrightHdr)
    fd.write(header)

    log_event_str += '};\n\n'
    fd.write(log_event_str)

    fd.write(string.join(print_log_entry, '\n'))

    fd.write(print_entry_start)
    fd.write(string.join(print_entry, '\n'))
    fd.write(print_entry_end)

    fd.write(footer)
    fd.close()



create_fred_wrappers_h()
create_syscallsreal_helper_c()
create_wrapper_util_h()
create_wrapper_util_cpp()
create_fred_read_log_h()
