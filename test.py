from sa_util import *
from rr_util import *
from pin_util import *
from get_watchpoints import *
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
    rr_backslice('909_ziptest_exe9', 0x409380, 0x409418, 0x409379, 'RDX', 0, 8, 'R13', {})
    # 0x40937D 0x409408 0x409379
    b = datetime.datetime.now()
    print("Took: " + str(b-a))

def test_rr_slice2():
    a = datetime.datetime.now()
    rr_backslice('909_ziptest_exe9', None, None, 0x40bcbd, 'RSI', 0, 0, None, {})
    b = datetime.datetime.now()
    print("Took: " + str(b-a))

def test_rr_slice3():
    a = datetime.datetime.now()
    rr_backslice('909_ziptest_exe9', None, None, 0x408b05, 'RSI', 0, 0, None, {})
    b = datetime.datetime.now()
    print("Took: " + str(b-a))

def test_get_all_bb():
    results = getAllBBs(0x416a91, 'bytes.*Buffer·Read', '909_ziptest_exe9')
    print(len(results))

def test_getting_static_addrs():
    prog = '909_ziptest_exe9'
    ret, ret1 = get_mem_writes_to_static_addrs(prog)
    print(ret)
    print(ret1)

def test_sa_slices():
    slice_starts = []
    #slice_starts.append(['rax', 4234536, 'sweep', True]) #why is the filtered against?
    slice_starts.append(['', 0x409c84, 'sweep', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices1():
    slice_starts = []
    ##slice_starts.append(['rax', 4234536, 'sweep', True]) #why is the filtered against?
    #slice_starts.append(['rax', 0x409418, 'scanblock', True])
    #slice_starts.append(['rax', 4234346, 'sweep', True])
    slice_starts.append(['rdx', 0x40a6aa, 'runtime.markallocated', True])
    #slice_starts.append(['rax', 4237718, 'runtime.markspan', True])
    #slice_starts.append(['rdx', 4238284, 'runtime.setblockspecial', True])
    ##slice_starts.append(['RAX', 4237997, 'runtime.unmarkspan', True])
    #slice_starts.append(['rax', 4237218, 'runtime.markfreed', True])

    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices2():
    slice_starts = []
    slice_starts.append(['', 4234294, 'sweep', False]) #0x409C36
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices3():
    slice_starts = []
    slice_starts.append(['', 0x43c46c, 'unicode.init', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices3_1():
    slice_starts = []
    slice_starts.append(['rax', 0x407bb2, 'runtime.new', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices4():
    slice_starts = []
    slice_starts.append(['', 0x40a9a6, 'runtime.markspan', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices5():
    slice_starts = []
    slice_starts.append(['rax', 0x429b97, 'compress/flate.*decompressor·huffmanBlock', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices6():
    slice_starts = []
    slice_starts.append(['', 4367815, 'compress/flate.*decompressor·moreBits', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices7():
    slice_starts = []
    slice_starts.append(['rbx', 0x42dfd7, 'os.NewError', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices8():
    slice_starts = []
    slice_starts.append(['', 0x4037ac, 'hash_subtable_new', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices9():
    slice_starts = []
    slice_starts.append(['', 0x408f78, 'runtime.addfinalizer', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices10():
    slice_starts = []
    slice_starts.append(['rax', 0x40bd4d, 'setaddrbucket', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices11(): #can encounter some indirect writes
    slice_starts = []
    slice_starts.append(['', 0x41101f, 'runtime.slicearray', False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices12():
    slice_starts = []
    slice_starts.append(['SPECIAL', 0x4037ac, "hash_subtable_new", False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices13():
    slice_starts = []
    #slice_starts.append(['', 0x41b70b, "fmt.newCache", False])
    #slice_starts.append(['rbx', 4346273, "fmt.init", False])
    slice_starts.append(['rbx', 4345826, "fmt.init", False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices14():
    slice_starts = []
    #slice_starts.append(['', 0x41b70b, "fmt.newCache", False])
    #slice_starts.append(['rbx', 4346273, "fmt.init", False])
    slice_starts.append(['', 4253023, "runtime.malg", False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices15(): #TODO fix
    slice_starts = []
    #slice_starts.append(['', 0x41b70b, "fmt.newCache", False])
    #slice_starts.append(['rbx', 4346273, "fmt.init", False])
    slice_starts.append(['SPECIAL', 4552810, "syscall.Syscall6", False])
    #slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices16():
    slice_starts = []
    #slice_starts.append(['', 0x41b70b, "fmt.newCache", False])
    #slice_starts.append(['rbx', 4346273, "fmt.init", False])
    #slice_starts.append(['SPECIAL', 0x41508f, "archive/zip.readDirectoryHeader", False])
    slice_starts.append(['', 0x415085, "archive/zip.readDirectoryHeader", False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(results)

def test_sa_slices17():
    slice_starts = []
    #slice_starts.append(['', 0x41b70b, "fmt.newCache", False])
    #slice_starts.append(['rbx', 4346273, "fmt.init", False])
    #slice_starts.append(['SPECIAL', 0x41508f, "archive/zip.readDirectoryHeader", False])
    #slice_starts.append(['SPECIAL', 0x43408a, "time.timerHeap·Push", False])
    #slice_starts.append(['SPECIAL', 0x42594c, "io.NewSectionReader", False])
    #slice_starts.append(['SPECIAL', 0x4251de, "fmt.init", False])
    #slice_starts.append(['RBX', 0x42dfd7, "os.NewError", False])
    #slice_starts.append(['SPECIAL', 0x4577b6, "syscall.init", False])
    #slice_starts.append(['RAX', 4215462, "runtime.makemap", False])
    #slice_starts.append(['RDX', 4215333, "runtime.makemap_c", False]) #TODO, why rsp is included?
    #slice_starts.append(['RAX', 4214693, "runtime.makemap_c", False]) #TODO check later to verify this is re-sliced

    #slice_starts.append(['SPECIAL', 0x415fb1, "archive/zip.init", False])
    #slice_starts.append(['RBX', 4382679, "os.NewError", False])
    #slice_starts.append(['RAX', 0x40627e, "copyin", False])
    slice_starts.append(['RBX', 0x4251a1, "fmt.init", False]) #TODO, implement check for intractable stack writes
    #slice_starts.append(['RDX', 0x402448, "runtime.makechan_c", False])
    #slice_starts.append(['SPECIAL', 0x40bd778, "setaddrbucket", False])
    results = static_backslices(slice_starts, '909_ziptest_exe9', {})
    print(len(results))

def test_watchpoint():
    breakpoints = []
    watchpoints = ['0x7fdc12590d5c']
    #run_watchpoint(breakpoints, watchpoints)
    ret = parse_watchpoint(breakpoints, watchpoints, '*0x43017d')
    for r in ret:
        print(r)

def main():
    #test_ins_trace()
    #test_func_trace()
    #test_rr_slice()
    #get_mem_writes_to_static_addrs('909_ziptest_exe9')
    #get_func_to_callsites('909_ziptest_exe9')
    #test_sa_slices3()
    #test_get_all_bb()
    #test_rr_slice()
    #test_getting_static_addrs()
    #test_sa_slices17()
    #test_watchpoint()
    #test_rr_slice3()
    test_sa_slices11()
 
if __name__ == "__main__":
    main()
