from sa_util import *
from rr_util import *
from pin_util import *
import datetime

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
    a = datetime.datetime.now()
    #rr_backslice('909_ziptest_exe9', 4234276, 'RBP', 0, 0, None)
    #rr_backslice('909_ziptest_exe9', 4234286, 4234325, 4234276, 'RBP', 0, 0, None)
    #rr_backslice('909_ziptest_exe9', 4234305, 4234325, 4234276, 'RBP', 0, 0, None)
    #rr_backslice('909_ziptest_exe9', 4232057, 'RDX', 0, 8, 'R13')
    #rr_backslice('909_ziptest_exe9', 4232061, 4232084, 4232057, 'RDX', 0, 8, 'R13')
    rr_backslice('909_ziptest_exe9', 4232061, 4232200, 4232057, 'RDX', 0, 8, 'R13')
    b = datetime.datetime.now()
    print("Took: " + str(b-a))

def test_sa_slices():
    slice_starts = []
    slice_starts.append(['rax', 4234536, 'sweep', True]) #why is the filtered against?
    slice_starts.append(['rax', 4232216, 'scanblock', True])
    slice_starts.append(['rax', 4234346, 'sweep', True])
    slice_starts.append(['rdx', 4236970, 'runtime.markallocated', True])
    slice_starts.append(['rax', 4237718, 'runtime.markspan', True])
    slice_starts.append(['rdx', 4238284, 'runtime.setblockspecial', True])
    #slice_starts.append(['RAX', 4237997, 'runtime.unmarkspan', True])
    slice_starts.append(['rax', 4237218, 'runtime.markfreed', True])
    results = static_backslices(slice_starts, '909_ziptest_exe9')
    print(results)

def main():
    #test_ins_trace()
    #test_func_trace()
    #test_rr_slice()
    #get_mem_writes_to_static_addrs('909_ziptest_exe9')
    #get_func_to_callsites('909_ziptest_exe9')
    test_sa_slices()
 
if __name__ == "__main__":
    main()
