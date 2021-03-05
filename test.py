from util import *

def test_ins_trace():
    #467, 472
    ret = are_predecessors_predictive([0x409c55], 0x409d47,\
    #472, 488
    #ret = are_predecessors_predictive([0x409c84], 0x409d47,\
            "/home/anygroup/perf_debug_tool", "909_ziptest_exe2", "test.zip")

    print(ret)

def test_func_trace():
    ret = trace_function('scanblock',\
            "/home/anygroup/perf_debug_tool", "909_ziptest_exe2", "test.zip")
    #print(ret)
    assert ret is not None

def test_rr_slice():
    rr_backslice('RBP', 0, 0, 4234276, 4234325, 4234372)

def main():
    #test_ins_trace()
    #test_func_trace()
    test_rr_slice()
 
if __name__ == "__main__":
    main()
