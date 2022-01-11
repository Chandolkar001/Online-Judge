import sys
from seccomp import *


def seccomp_filter():
    rule = SyscallFilter(defaction=KILL)
    rule.add_rule(ALLOW, "read", Arg(0, EQ, sys.stdin.fileno()))
    rule.add_rule(ALLOW, "write", Arg(0, EQ, sys.stdout.fileno()))
    rule.add_rule(ALLOW, "write", Arg(0, EQ, sys.stderr.fileno()))
    rule.add_rule(ALLOW, "fstat")   #obtain information about an open file
    rule.add_rule(ALLOW, 'ioctl')   #input output system call
    rule.add_rule(ALLOW, "exit_group")  #termiates all thread
    rule.add_rule(ALLOW, "exit")    #terminates calling thread
    rule.add_rule(ALLOW, "read")
    rule.add_rule(ALLOW, "openat")   #open a file relative to a directory file descriptor 
    rule.add_rule(ALLOW, "lseek")   #changes the positions of the read/write pointer within the file
    rule.add_rule(ALLOW, "close")
    rule.add_rule(ALLOW, "mmap")    #map files or devices into memory
    rule.add_rule(ALLOW, "mprotect")    #set protection on a region of memory
    rule.add_rule(ALLOW, "sigreturn")   #return from signal handler
    rule.add_rule(ALLOW, "sigaltstack") #set and/or get signal stack context
    rule.add_rule(ALLOW, "execve")  #execute program
    rule.add_rule(ALLOW, "execveat")    #execute program relative to a directory file descriptor
    rule.add_rule(ALLOW, "brk") #change size of data segment
    rule.add_rule(ALLOW, "munmap")  #unmap files or devices into memory
    rule.add_rule(ALLOW, "access")  #determines whether the calling process has access permission to a file
    rule.load()


seccomp_filter()
print(int(input())+10)
