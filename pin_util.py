from __future__ import division
import os
import os.path
import sys
sys.path.append(os.path.abspath('./pin'))
from instruction_reg_trace import *
from instruction_trace import *
from function_trace import *
from bit_trace import *
#https://stackoverflow.com/questions/145270/calling-c-c-from-python

curr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG_CTYPE = True
DEBUG = True

################################################################
#### Helper functions that interact with PIN functionalities ###
################################################################
def are_predecessors_predictive(succe, prede, path, prog, arg):
    trace = InsTrace(os.path.join(path, prog) + " " + arg, pin='~/pin-3.11/pin')
    ret = trace.get_predictive_predecessors(succe, prede)
    return ret

def trace_function(function, path, prog, arg):
    trace = TraceCollector(os.path.join(path, prog) + " " + arg, pin='~/pin-3.11/pin')
    trace.run_function_trace(function)
    trace.read_trace_from_disk(function)
    #trace.cleanup(function)
    return trace.traces[function]
