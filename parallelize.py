import sys
import os
import shutil
import multiprocessing as mp
import threading
import json
import datetime




def run_task(id, pipe):
    os.chdir('run_{}'.format(id))
    sys.path.insert(0, os.getcwd())
    sys.path.insert(2, os.path.join(os.getcwd(), 'rr'))
    import rr_util
    while True:
        obj = pipe.recv()
        if obj == "Shutdown":
            break
        (prog, a1, a2, a3, a4, a5, a6, a7) = obj
        str_args = '_'.join(map(lambda arg : "None" if arg is None else arg, [prog, a1, a2, a3, a4, a5, a6, a7]))
        print("Process {} recive task {}".format(id, str_args))
        rr_result_cache = {}
        start_time = datetime.datetime.now()
        rr_util.rr_backslice2(prog, a1, a2, a3, a4, a5, a6, a7, rr_result_cache)
        duraton = datetime.time.now() - start_time
        print("Process {} finish task {} in {}".format(id, str_args, duraton))
        pipe.send(rr_result_cache)
    pipe.send("Shutdown")




def main():
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    num_processor = 16
    prog = '909_ziptest_exe9'
    if len(sys.argv) > 1:
        prog = sys.argv[1]

    print("Setting up parallel environment")
    for i in range(num_processor):
        process_dir = os.path.join(curr_dir, 'run_{}'.format(i))
        if not os.path.exists(process_dir):
            os.mkdir(process_dir)
        rr_dir = os.path.join(process_dir, 'rr')
        if os.path.exists(rr_dir):
            shutil.rmtree(rr_dir)
        shutil.copytree('rr', rr_dir, ignore=shutil.ignore_patterns('.*', '_*'))
        shutil.copy('rr_util.py', process_dir)
        shutil.copy('sa_util.py', process_dir)
        shutil.copy(prog, process_dir)
        binary_dir = os.path.join(process_dir, 'binary_analysis')
        if os.path.exists(binary_dir):
            shutil.rmtree(binary_dir)
        shutil.copytree('binary_analysis', binary_dir, ignore=shutil.ignore_patterns('.*', '_*'))

    rr_result_cache = {}

    print("Starting execution")
    for i in range(5):
        print("In iteration {}".format(i))
        start_time = datetime.datetime.now()
        os.system('rm rr_inputs')
        os.system('python3 static_dep_graph.py >> out')
        lines = open('rr_inputs', 'r').readlines()
        print("Stdtic dep graph took: {}".format(datetime.datetime.now() - start_time()))
        print("Static dep graph produces {} inputs".format(len(lines)))


        def send_task(pipe):
            while True:
                try:
                    line = lines.pop()
                except IndexError:
                    break
                if line.startswith(prog):
                    line = line[len(prog):]
                segs = line.split('_')
                a0 = None if segs[0].strip() == "None" else segs[0].strip()
                a1 = None if segs[1].strip() == "None" else segs[1].strip() 
                a2 = None if segs[2].strip() == "None" else segs[2].strip() 
                a3 = None if segs[3].strip() == "None" else segs[3].strip() 
                a4 = None if segs[4].strip() == "None" else segs[4].strip() 
                a5 = None if segs[5].strip() == "None" else segs[5].strip() 
                a6 = None if segs[6].strip() == "None" else segs[6].strip() 
                a7 = None if segs[7].strip() == "None" else segs[7].strip() 
                pipe.send((prog, a1, a2, a3, a4, a5, a6, a7))
                print("Send task {}".format(line))
                result_cache = pipe.recv()
                print("Receiving result for task {}".format(line))
                for key, value in result_cache.items():
                    rr_result_cache[key] = value
                
            pipe.send("Shutdown")
            while pipe.recv() != "Shutdown":
                pipe.send("Shutdown")

        start_time = datetime.datetime.now()
        processes = []
        threads = []
        mp.set_start_method('spawn')
        for i in range(num_processor):
            parent_conn, child_conn = mp.Pipe(duplex=True)
            p = mp.Process(target = run_task, args=(i, child_conn))
            p.start()
            processes.append(p)
            t = threading.Thread(target=send_task, args=(parent_conn, ))
            t.start()
            threads.append(t)

        for i in range(num_processor):
            processes[i].join()
            threads[i].join()
        json.dump(rr_result_cache, open(os.path.join(curr_dir, 'cache', 'rr_results_{}.json'.format(prog))))

        duration = datetime.datetime.now() - start_time
    print("Running iteration {} uses {} seconds".format(i, duration))

if __name__ == '__main__':
    main()