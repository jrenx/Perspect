# perf_debug_tool
# to run on 909:
python3 main.py -f sweep -i 0x409daa -r rdi -p 909_ziptest_exe6 -a test.zip
# this starts the analysis at line 500 of the sweep function

# to get the filename:linenumber of a binary address:
addr2line 0x409daa -e 909_ziptest_exe6
