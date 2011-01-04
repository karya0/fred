#!/usr/bin/python

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

import fcntl
import os
import pty
import readline
import re
import sys
import signal
import threading

import fredutil

# Maximum length of a prompt string (from any debugger)
GN_MAX_PROMPT_LENGTH = 32
# Maximum length of a string for requesting additional user input
gn_max_need_input_length = 0

gn_child_pid = -1
gn_child_fd = None
gb_prompt_ready = False
gb_hide_output = False
gb_capture_output = False
gb_capture_output_til_prompt = False
gs_captured_output = ""
g_capture_output_event = threading.Event()
gre_prompt = ""
g_find_prompt_function = None
g_print_prompt_function = None
gls_needs_user_input = []
gb_need_user_input = False

class ThreadedOutput(threading.Thread):
    def run(self):
        global gb_prompt_ready, gb_capture_output, gs_captured_output, \
               g_capture_output_event, gb_capture_output_til_prompt, \
               gb_hide_output, gn_max_need_input_length, gb_need_user_input
        # Last printed will be the last 'n' characters printed from child. This
        # is so we can know when the debugger prompt has been printed to
        # screen.
        last_printed = ""
        # Used to detect when debugger needs additional user input
        last_printed_need_input = ""
        while 1:
            output = get_child_output()
            if output != None:
                last_printed = fredutil.last_n(last_printed, output,
                                               GN_MAX_PROMPT_LENGTH)
                last_printed_need_input = \
                    fredutil.last_n(last_printed_need_input, output,
                                    gn_max_need_input_length)
                if gb_capture_output:
                    gs_captured_output += output
                    if gb_capture_output_til_prompt:
                        if g_find_prompt_function(last_printed):
                            g_capture_output_event.set()
                    else:
                        g_capture_output_event.set()
                if not gb_hide_output:
                    # Always remove prompt from output so we can print it:
                    output = re.sub(gre_prompt, '', output)
                    sys.stdout.write(output)
                    sys.stdout.flush()
            # Always keep these up-to-date:
            gb_prompt_ready = g_find_prompt_function(last_printed)
            gb_need_user_input = match_needs_user_input(last_printed_need_input)

def start_output_thread():
    """Start the output thread in daemon mode.
    A thread in daemon mode will not be joined upon program exit."""
    o = ThreadedOutput()
    o.daemon = True
    o.start()

def send_child_input(input):
    """Write the given input string to the child process."""
    global gn_child_fd
    os.write(gn_child_fd, input)
        
def get_child_output():
    """Read and return a string of output from the child process."""
    global gn_child_fd
    try:
        output = os.read(gn_child_fd, 1000)
    except:
        return None
    return output

def wait_for_prompt():
    """Spin until the global gb_prompt_ready flag has been set to True.
    gb_prompt_ready is set by the output thread."""
    global gb_prompt_ready, gb_need_user_input
    while not gb_prompt_ready:
        if gb_need_user_input:
            # Happens when, for example, gdb prints more than one screen,
            # and the user must press 'return' to continue printing.
            user_input = raw_input().strip()
            send_child_input(user_input + '\n')
            gb_need_user_input = False
        pass
    # Reset for next time
    gb_prompt_ready = False

def start_output_capture(wait_for_prompt):
    """Start recording output from child into global gs_captured_output.
    wait_for_prompt flag will cause all output until the next debugger prompt
    to be saved."""
    global gb_capture_output, gs_captured_output, g_capture_output_event, \
           gb_capture_output_til_prompt
    gb_capture_output_til_prompt = wait_for_prompt
    gb_capture_output = True
    g_capture_output_event.clear()

def wait_for_captured_output(wait_for_prompt):
    """Wait until output capture is done, and return captured output.
    The actual output capture is done by the output thread, and placed into
    global gs_captured_output. This function resets that global string when
    finished."""
    global gb_capture_output, gs_captured_output, g_capture_output_event, \
           gb_capture_output_til_prompt
    gb_capture_output_til_prompt = wait_for_prompt
    g_capture_output_event.wait()
    output = gs_captured_output
    gs_captured_output = ""
    gb_capture_output = False
    return output

def get_child_response(input, hide=True, wait_for_prompt=False):
    """Sends requested input to child, and returns any response made.
    If hide flag is True (default), suppresses echoing from child.  If
    wait_for_prompt flag is True, collects output until the debugger prompt is
    ready."""
    global gb_hide_output
    b_orig_hide_state = gb_hide_output
    gb_hide_output = hide
    start_output_capture(wait_for_prompt)
    send_child_input(input)
    response = wait_for_captured_output(wait_for_prompt)
    gb_hide_output = b_orig_hide_state
    return response

def set_max_needs_input_length():
    """Sets correct value of gn_max_need_input_length."""
    global gn_max_need_input_length, gls_needs_user_input
    n_max = 0
    for item in gls_needs_user_input:
        if len(item) > n_max:
            n_max = len(item)
    gn_max_need_input_length = n_max

def match_needs_user_input(s_str):
    """Return True if any regexes in gls_needs_user_input match 's_str'."""
    global gls_needs_user_input
    for item in gls_needs_user_input:
        if re.search(item, s_str) != None:
            return True
    return False

def fred_completer(text, state):
    """Custom completer function called when the user presses TAB."""
    s_current_cmd = readline.get_line_buffer()
    # Write partial command+\t to debuggerso it can do the completion.
    result = get_child_response(s_current_cmd + '\t')
    # Erase what text we already have:
    result = result.replace(s_current_cmd, "")
    readline.insert_text(result)

def spawn_child(argv):
    """Spawn a child process using the given command array."""
    global gn_child_pid, gn_child_fd
    fredutil.fred_debug("Starting child '%s'" % str(argv))
    (gn_child_pid, gn_child_fd) = pty.fork()
    if gn_child_pid == 0:
        os.execvp(argv[0], argv)

def kill_child():
    """Kill the child process."""
    global gn_child_fd
    if gn_child_pid == -1:
      return
    fredutil.fred_debug("Killing child process pid %d", gn_child_pid)
    signal_child(signal.SIGKILL)
    os.close(gn_child_fd)
    
def signal_child(signum):
    """Send the signal to the child process."""
    global gn_child_pid
    os.kill(gn_child_pid, signum)

def child_is_alive():
    """Return True if the child process is still alive; False if not."""
    try:
        signal(0)
    except:
        return False
    return True

def get_child_pid():
    """Return the current child pid."""
    global gn_child_pid
    return gn_child_pid

def get_command():
    """Get a command from the user using raw_input."""
    global g_print_prompt_function
    return raw_input(g_print_prompt_function()).strip()
    #return raw_input("!").strip()

def send_command(command):
    """Send a command to the child process."""
    send_child_input(command+'\n')

def send_command_blocking(command):
    """Send a command to the child process and wait for the prompt."""
    send_child_input(command+'\n')
    wait_for_prompt()
    
def reexec(argv):
    """Replace the current child process with the new given one."""
    fredutil.fred_debug("Replacing current child with '%s'" % str(argv))
    spawn_child(argv)

def setup(find_prompt_fnc, print_prompt_fnc, prompt_re, ls_needs_user_input,
          argv):
    """Perform any setup needed to do i/o with the child process."""
    global g_find_prompt_function, g_print_prompt_function, gre_prompt, \
           gls_needs_user_input
    g_find_prompt_function = find_prompt_fnc
    g_print_prompt_function = print_prompt_fnc
    gre_prompt = prompt_re
    gls_needs_user_input = ls_needs_user_input
    set_max_needs_input_length()
    # Enable tab completion (with our own 'completer' function)
    #readline.parse_and_bind('tab: complete')
    #readline.set_completer(fred_completer)
    spawn_child(["dmtcp_checkpoint", "--port", os.environ["DMTCP_PORT"]] + argv)
    start_output_thread()

def teardown():
    """Perform any cleanup associated with FReD exit."""
    kill_child()