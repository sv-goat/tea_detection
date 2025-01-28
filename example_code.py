import os

def foo(x):
    return x

user_input = input("Enter command: ")  # tainted source
cmd = "ls " + "whomst" + user_input  # propagated from user_input to cmd
ret = foo(cmd) # propagated from cmd to ret
yp = "5"
exec(ret) # reached to sink
exec(yp)