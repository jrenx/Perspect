import unittest
from sa_util import *
from rr_util import *
from pin_util import *
from get_watchpoints import *
import datetime

class TestPIN(unittest.TestCase):
    def test_ins_trace(self):
        # 467, 472
        ret = are_predecessors_predictive([0x409c55], 0x409d47, \
                                          # 472, 488
                                          # ret = are_predecessors_predictive([0x409c84], 0x409d47,\
                                          "/home/anygroup/perf_debug_tool", "909_ziptest_exe2", "test.zip")
        self.assertNotEqual(ret, None)

    def test_func_trace(self):
        ret = trace_function('scanblock', "/home/anygroup/perf_debug_tool", "909_ziptest_exe2", "test.zip")
        # print(ret)
        self.assertNotEqual(ret, None)


class TestRR(unittest.TestCase):
    def test_rr_slice(self):
        a = datetime.datetime.now()
        # rr_backslice('909_ziptest_exe9', 4234276, 'RBP', 0, 0, None)
        # rr_backslice('909_ziptest_exe9', 4234286, 4234325, 4234276, 'RBP', 0, 0, None)
        # rr_backslice('909_ziptest_exe9', 4234305, 4234325, 4234276, 'RBP', 0, 0, None)
        # rr_backslice('909_ziptest_exe9', 4232057, 'RDX', 0, 8, 'R13')
        # rr_backslice('909_ziptest_exe9', 4232061, 4232084, 4232057, 'RDX', 0, 8, 'R13')
        rr_backslice('909_ziptest_exe9', 0x409380, 0x409418, 0x409379, 'RDX', 0, 8, 'R13', {})
        # 0x40937D 0x409408 0x409379
        b = datetime.datetime.now()
        print("Took: " + str(b - a))

    def test_rr_slice2(self):
        a = datetime.datetime.now()
        rr_backslice('909_ziptest_exe9', None, None, 0x40bcbd, 'RSI', 0, 0, None, {})
        b = datetime.datetime.now()
        print("Took: " + str(b - a))

    def test_rr_slice3(self):
        a = datetime.datetime.now()
        rr_backslice('909_ziptest_exe9', None, None, 0x408b05, 'RSI', 0, 0, None, {})
        b = datetime.datetime.now()
        print("Took: " + str(b - a))

    def test_watchpoint(self):
        breakpoints = []
        watchpoints = ['0x7fdc12590d5c']
        # run_watchpoint(breakpoints, watchpoints)
        ret = parse_watchpoint(breakpoints, watchpoints, '*0x43017d')
        for r in ret:
            print(r)

class TestSA(unittest.TestCase):
    def test_get_all_bb(self):
        results = getAllBBs(0x416a91, 'bytes.*Buffer·Read', '909_ziptest_exe9')
        print(len(results))

    def test_getting_static_addrs(self):
        prog = '909_ziptest_exe9'
        ret, ret1 = get_mem_writes_to_static_addrs(prog)
        print(ret)
        print(ret1)

class TestStaticSlicing(unittest.TestCase):
    def test_basic(self):
        slice_starts = []
        slice_starts.append(['', 0x409c84, 'sweep', False])
        # the bits variable @ test for bit special mgc0.c:472
        slice_starts.append(['', 0x409c36, 'sweep', False])
        # the bits variable @ test for bit allocated mgc0.c:464
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], 0x409c84)
        self.assertEqual(results[1][0], '')
        self.assertEqual(results[1][1], 0x409c36)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(len(results[1][2]), 1)
        self.assertEqual(results[0][2][0], results[1][2][0])
        # first boolean: read_same_as_write | second boolean: is_bit_var
        self.assertEqual(results[0][2][0], [0x409c24, 'RBP', 0, 0, None, False, True, 'memread', 'sweep'])

    def test_bit_var(self):
        slice_starts = []
        slice_starts.append(['rax', 0x409d28, 'sweep', True]) # mark unallocated
        slice_starts.append(['rax', 0x409c6a, 'sweep', True]) # unmark
        slice_starts.append(['rax', 0x409418, 'scanblock', True]) # mark

        slice_starts.append(['rdx', 0x40a6aa, 'runtime.markallocated', True])
        slice_starts.append(['rax', 0x40a7a2, 'runtime.markfreed', True])

        slice_starts.append(['rax', 0x40a996, 'runtime.markspan', True])
        slice_starts.append(['rax', 0x40aaad, 'runtime.unmarkspan', True])

        slice_starts.append(['rdx', 0x40abcc, 'runtime.setblockspecial', True])

        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], 'rax')
        self.assertEqual(results[0][1], 0x409d28)
        self.assertEqual(len(results[0][2]), 1)
        # first boolean: read_same_as_write | second boolean: is_bit_var
        self.assertEqual(results[0][2][0], [0x409d0e, 'RBP', 0, 0, None, True, True, 'memread', 'sweep'])

        self.assertEqual(results[1][0], 'rax')
        self.assertEqual(results[1][1], 0x409c6a)
        self.assertEqual(len(results[1][2]), 1)
        self.assertEqual(results[1][2][0], [0x409c6a, 'RBP', 0, 0, None, True, True, 'memread', 'sweep'])

        self.assertEqual(results[2][0], 'rax')
        self.assertEqual(results[2][1], 0x409418)
        self.assertEqual(len(results[2][2]), 1)
        self.assertEqual(results[2][2][0], [0x409418, 'R9', 0, 0, None, True, True, 'memread', 'scanblock'])

        self.assertEqual(results[3][0], 'rdx')
        self.assertEqual(results[3][1], 0x40a6aa)
        self.assertEqual(len(results[3][2]), 1)
        self.assertEqual(results[3][2][0], [0x40a652, 'RSI', 0, 0, None, True, True, 'memread', 'runtime.markallocated'])

        self.assertEqual(results[4][0], 'rax')
        self.assertEqual(results[4][1], 0x40a7a2)
        self.assertEqual(len(results[4][2]), 1)
        self.assertEqual(results[4][2][0], [0x40a763, 'RBP', 0, 0, None, True, True, 'memread', 'runtime.markfreed'])

        self.assertEqual(results[5][0], 'rax')
        self.assertEqual(results[5][1], 0x40a996)
        self.assertEqual(len(results[5][2]), 1)
        self.assertEqual(results[5][2][0], [0x40a97d, 'RBX', 0, 0, None, True, True, 'memread', 'runtime.markspan'])

        self.assertEqual(results[6][0], 'rax')
        self.assertEqual(results[6][1], 0x40aaad)
        self.assertEqual(len(results[6][2]), 0)

        self.assertEqual(results[7][0], 'rdx')
        self.assertEqual(results[7][1], 0x40abcc)
        self.assertEqual(len(results[7][2]), 1)
        self.assertEqual(results[7][2][0], [0x40aba3, 'RBP', 0, 0, None, True, True, 'memread', 'runtime.setblockspecial'])

    def test_stack_and_pass_by_reference(self):
        slice_starts = []
        slice_starts.append(['', 0x43c46c, 'unicode.init', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], 0x43c46c)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x407bb2, 'RAX', 0, 0, None, False, False, 'regread', 'runtime.new'])

    def test_pass_by_reference(self):
        slice_starts = []
        slice_starts.append(['rax', 0x407bb2, 'runtime.new', False])
        # slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], 'rax')
        self.assertEqual(results[0][1], 0x407bb2)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x4072e5, 'RSP', 0, 48, None, False, False, 'memread', 'runtime.mallocgc'])

    def test_stack_param(self):
        slice_starts = []
        slice_starts.append(['', 0x40a9a6, 'runtime.markspan', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        #TODO, dyninst has a bug that would not further slice one assignment,
        # so it's returned as a result.
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], 0x40a9a6)
        #self.assertEqual(len(results[0][2]), 1)
        self.assertTrue((results[0][2][0] == [0x4087af, 'RAX', 0, 0, None, False, False, 'regread', 'MCentral_Grow'])
                    or (results[0][2][1] == [0x4087af, 'RAX', 0, 0, None, False, False, 'regread', 'MCentral_Grow']))

        print(results)

    def test_stack_param1(self):
        slice_starts = []
        slice_starts.append(['rax', 0x429b97, 'compress/flate.*decompressor·huffmanBlock', False])
        # slice_starts.append(['', int('0x43c45c', 16), 'unicode.init', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], 'rax')
        self.assertEqual(results[0][1], 0x429b97)
        self.assertEqual(len(results[0][2]), 3)
        self.assertTrue([0x429f38, 'RAX', 0, 0, None, False, False, 'regread', 'compress/flate.*decompressor·copyHuff'] in results[0][2])
        self.assertTrue([0x428d32, 'RAX', 0, 0, None, False, False, 'regread', 'compress/flate.*decompressor·nextBlock'] in results[0][2])
        self.assertTrue([0x428dac, 'RAX', 0, 0, None, False, False, 'regread', 'compress/flate.*decompressor·nextBlock'] in results[0][2])

    def test_stack_intractable(self):
        slice_starts = []
        slice_starts.append(['rbx', 0x42dfd7, 'os.NewError', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], 'rbx')
        self.assertEqual(results[0][1], 0x42dfd7)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x42dfd2, 'RSP', 0, 40, None, False, False, 'memread', 'os.NewError'])

    def test_pass_by_reference_intractable_conservative(self):
        slice_starts = []
        slice_starts.append(['', 0x408f78, 'runtime.addfinalizer', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], 0x408f78)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x408f73, 'RSP', 0, 88, None, False, False, 'memread', 'runtime.addfinalizer'])
        #self.assertEqual(results[0][2][0], [0x4072e5, 'RSP', 0, 48, None, False, False, 'memread', 'runtime.mallocgc'])

    def test_stack_and_pass_by_reference(self):
        slice_starts = []
        slice_starts.append(['rax', 0x40bd4d, 'setaddrbucket', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], 'rax')
        self.assertEqual(results[0][1], 0x40bd4d)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x4072e5, 'RSP', 0, 48, None, False, False, 'memread', 'runtime.mallocgc'])

    def test_pass_by_reference_intractable_conservative1(self): #TODO FIX
        #TODO this is a bug, static analysis seems to have returned the wrong insn
        slice_starts = []
        slice_starts.append(['rbx', 0x424fe2, "fmt.init", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], 'rbx')
        self.assertEqual(results[0][1], 0x424fe2)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x424fdd, 'RSP', 0, 16, None, False, False, 'memread', 'fmt.init'])

    def test_stack_param2(self):
        slice_starts = []
        slice_starts.append(['', 0x41b70b, "fmt.newCache", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], 0x41b70b)
        self.assertEqual(len(results[0][2]), 2)
        self.assertTrue([0x424fe2, 'RBX', 0, 0, None, False, False, 'regread', 'fmt.init'] in results[0][2])
        self.assertTrue([0x4251a1, 'RBX', 0, 0, None, False, False, 'regread', 'fmt.init'] in results[0][2])

    def test_pass_by_reference_intractable_conservative2(self): #TODO fix
        slice_starts = []
        slice_starts.append(['rbx', 0x4251a1, "fmt.init", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], 'rbx')
        self.assertEqual(results[0][1], 0x4251a1)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x42519c, 'RSP', 0, 16, None, False, False, 'memread', 'fmt.init'])

    def test_pass_by_reference_intractable_conservative3(self): #TODO fix
        slice_starts = []
        slice_starts.append(['', 0x40e55f, "runtime.malg", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], 0x40e55f)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x40e55f, 'RSP', 0, 40, None, False, False, 'memread', 'runtime.malg'])

    def test_pass_by_reference_intractable_conservative4(self):
        slice_starts = []
        slice_starts.append(['SPECIAL', 0x43408a, "time.timerHeap·Push", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'special')
        self.assertEqual(results[0][1], 0x43408a)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x434068, 'RSP', 0, 32, None, False, False, 'memread', 'time.timerHeap·Push'])

    def test_pass_by_reference_intractable_conservative5(self): #TODO fix
        slice_starts = []
        slice_starts.append(['SPECIAL', 0x42594c, "io.NewSectionReader", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'special')
        self.assertEqual(results[0][1], 0x42594c)
        self.assertEqual(len(results[0][2]), 3)
        self.assertTrue([0x413e16, 'RBP', 0, 0, None, False, False, 'regread', 'archive/zip.*Reader·init'] in results[0][2])
        self.assertTrue([0x4140f1, 'RSI', 0, 16, 'DS', False, False, 'memread', 'archive/zip.*File·Open'] in results[0][2])
        self.assertTrue([0x41421e, 'RSI', 0, 16, 'DS', False, False, 'memread', 'archive/zip.*File·Open'] in results[0][2])

    def test_stack_return(self):
        slice_starts = []
        slice_starts.append(['SPECIAL', 0x4251de, "fmt.init", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'special')
        self.assertEqual(results[0][1], 0x4251de)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x42dfd7, 'RBX', 0, 0, None, False, False, 'regread', 'os.NewError'])

    def test_pass_by_reference_intractable_conservative6(self):
        slice_starts = []
        slice_starts.append(['RBX', 0x42dfd7, "os.NewError", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'rbx')
        self.assertEqual(results[0][1], 0x42dfd7)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x42dfd2, 'RSP', 0, 40, None, False, False, 'memread', 'os.NewError'])

    def test_stack_return1(self):
        slice_starts = []
        slice_starts.append(['SPECIAL', 0x4577b6, "syscall.init", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'special')
        self.assertEqual(results[0][1], 0x4577b6)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x4052a6, 'RAX', 0, 0, None, False, False, 'regread', 'runtime.makemap'])

    def test_stack_return2(self):
        slice_starts = []
        slice_starts.append(['RAX', 0x4052a6, "runtime.makemap", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'rax')
        self.assertEqual(results[0][1], 0x4052a6)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x405225, 'RDX', 0, 0, None, False, False, 'regread', 'runtime.makemap_c'])

    #def test_sa_pass_by_reference_intractable_conservative7(self):
    def test_stack(self):
        slice_starts = []
        slice_starts.append(['RDX', 0x405225, "runtime.makemap_c", False]) #TODO, why rsp is included?
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'rdx')
        self.assertEqual(results[0][1], 0x405225)
        #TODO, dyninst has a bug that would slice RSP even though we didn't tell it to?
        #     or, because we don't full understand how dyninst works ... anyways
        #     as a result two results are returned, but is harmless for now
        self.assertEqual(len(results[0][2]), 2)
        self.assertTrue([0x404fa5, 'RAX', 0, 0, None, False, False, 'regread', 'runtime.makemap_c'] in results[0][2])
        self.assertTrue([0x404edc, '', 0, 0, None, False, False, 'empty', 'runtime.makemap_c'] in results[0][2])

    def test_stack_and_pass_by_reference1(self):
        slice_starts = []
        slice_starts.append(['RAX', 0x404fa5, "runtime.makemap_c", False]) #TODO check later to verify this is re-sliced
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], 'rax')
        self.assertEqual(results[0][1], 0x404fa5)
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], [0x4072e5, 'RSP', 0, 48, None, False, False, 'memread', 'runtime.mallocgc'])
    """
    def test_sa_slices26(self):
        slice_starts = []
        slice_starts.append(['SPECIAL', 0x415fb1, "archive/zip.init", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], )
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], )

    def test_sa_slices27(self):
        slice_starts = []
        slice_starts.append(['RBX', 4382679, "os.NewError", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], )
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], )

    def test_sa_slices28(self):
        slice_starts = []
        slice_starts.append(['RAX', 0x40627e, "copyin", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], )
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], )

    def test_sa_slices29(self):
        slice_starts = []
        slice_starts.append(['RBX', 0x4251a1, "fmt.init", False])  # TODO, implement check for intractable stack writes
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], )
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], )

    def test_sa_slices30(self):
        slice_starts = []
        slice_starts.append(['RDX', 0x402448, "runtime.makechan_c", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], )
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], )

    def test_sa_slices31(self):
        slice_starts.append(['SPECIAL', 0x40bd778, "setaddrbucket", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(len(results))
        self.assertEqual(results[0][0], '')
        self.assertEqual(results[0][1], )
        self.assertEqual(len(results[0][2]), 1)
        self.assertEqual(results[0][2][0], )
    """
    """ 
    def test_sa_TODO15(self):  # TODO fix
        slice_starts = []
        #TODO, might be a bug, see how we got here in the first place
        slice_starts.append(['SPECIAL', 0x45786a, "syscall.Syscall6", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        
    def test_sa_TODO16(self):
        slice_starts = []
        #TODO, might be a bug, see how we got here in the first place
        slice_starts.append(['', 0x415085, "archive/zip.readDirectoryHeader", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)

    def test_sa_TODO17(self):
        slice_starts = []
        #TODO, might be a bug, see how we got here in the first place
        slice_starts.append(['SPECIAL', 0x41508f, "archive/zip.readDirectoryHeader", False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
        
    def test_sa_TODO8(self):
        #TODO: load effective address in an operation in itself, this should not be traceable to a malloc
        #confirmed, this is a fake pointer! although, not really like a 64bit address, need to double check if indeed marked
        slice_starts = []
        slice_starts.append(['', 0x4037ac, 'hash_subtable_new', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
    def test_sa_TODO11(self):  # can encounter some indirect writes
        slice_starts = []
        #TODO, another lea, addr is 0xf840041000, and is written to by a repeated copyin loop at 0x42adbb, probably another fake pointer
        slice_starts.append(['', 0x41101f, 'runtime.slicearray', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
    """
    """
    def test_sa_slices6(self):
        slice_starts = []
        slice_starts.append(['', 0x42a5c7, 'compress/flate.*decompressor·moreBits', False])
        results = static_backslices(slice_starts, '909_ziptest_exe9', {})
        print(results)
    """
if __name__ == "__main__":
    unittest.main()
