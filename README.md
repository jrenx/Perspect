# perf_debug_tool
# to run on 909:
python3 main.py -f sweep -i 0x409daa -r rdi -p 909_ziptest_exe9 -a test.zip
# this starts the analysis at line 500 of the sweep function

# the 9 at the end of 909_ziptest_exe9 means iterating 9 times
# the 9 at the end of 909_ziptest_exe2 means iterating 2 times

# to get the filename:linenumber of a binary address:
addr2line 0x409daa -e 909_ziptest_exe9

