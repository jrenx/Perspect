import sys
import os
import shutil
import multiprocessing as mp
import threading
import json
import datetime
import time
import traceback
import socketserver
import queue
import _thread

HOST, PORT = "localhost", 9999
q = queue.Queue()
DEBUG = True
num_processor = 16
num_new_unique_inputs_received = 0
handled = set()

pending_count_lock = threading.Lock()
pending_count = 0

restart_static_slicing_lock = threading.Lock()
restart_static_slicing = False

rr_result_cache_lock = threading.Lock()
rr_result_cache = {}

it_lock = threading.Lock()
it = 0

class MyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        global num_new_unique_inputs_received
        self.data = self.rfile.readline().strip().decode("utf-8")
        if self.data == "FIN":
            print("[main receiver] Received FIN.")
            if num_new_unique_inputs_received > 0:
                print("[main receiver] Should restart static slicing... "
                      "number of new inputs received in previous run is: " + str(num_new_unique_inputs_received))
                num_new_unique_inputs_received = 0
                if q.empty():
                    rr_result_cache_lock.acquire()
                    json.dump(rr_result_cache, open(rr_result_file, 'w'), indent=4)
                    rr_result_cache_lock.release()

                    it_lock.acquire()
                    global it
                    it += 1
                    it_local = it
                    it_lock.release()
                    print("[main receiver] Execution of static slicing pass {} starts at {}".format(it_local, \
                            datetime.datetime.strftime(datetime.datetime.now(),"%Y/%m/%d, %H:%M:%S")), flush=True)
                    os.system('python3 static_dep_graph.py --parallelize_rr >> out{} &'.format(it_local))
                else:
                    restart_static_slicing_lock.acquire()
                    global restart_static_slicing
                    restart_static_slicing = True
                    restart_static_slicing_lock.release()
            else:
                print("[main receiver] Did not receive any new unique inputs, finish now...")
                for i in range(0, num_processor):
                    q.put(self.data)
        else:
            print("[main receiver] " + str(self.client_address[0]) + " wrote:" + str(self.data))
            line = self.data.strip()
            if line in handled:
                print("[main receiver] Ignore input already explored in this iteration: " + line, flush=True)
                return
            handled.add(line)
            q.put(line)
            num_new_unique_inputs_received += 1
            pending_count_lock.acquire()
            global pending_count
            pending_count += 1
            pending_count_lock.release()

def server_thread(server):
        server.serve_forever()

def run_task(id, pipe, prog):
    os.chdir('run_{}'.format(id))
    sys.path.insert(0, os.getcwd())
    sys.path.insert(2, os.path.join(os.getcwd(), 'rr'))
    pid = str(os.getpid())
    import rr_util
    import sa_util
    binary_ptr = sa_util.setup(prog)
    while True:
        try:
            obj = pipe.recv()
        except EOFError:
            #print("Received EOFError, retry...")
            continue
        if obj == "Shutdown":
            break
        (prog, a1, a2, a3, a4, a5, a6, a7) = obj
        str_args = '_'.join(map(lambda arg : "None" if arg is None else arg, [prog, a1, a2, a3, a4, a5, a6, a7]))
        print("[worker][{}] recive task {}".format(id, str_args),flush=True)
        rr_result_cache = {}
        start_time = datetime.datetime.now()
        try:
            rr_util.rr_backslice2(binary_ptr, prog, a1, a2, a3, a4, a5, a6, a7, rr_result_cache)
        except Exception as e:
            print("[rr][" + pid + "][ERROR] Calling RR failed for input: " + str(str_args))
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)
        duraton = datetime.datetime.now() - start_time
        print("[worker][{}] finish task {} in {}".format(id, str_args, duraton),flush=True)
        pipe.send(rr_result_cache)
    print("[worker][{}] finished execution.".format(id),flush=True)
    pipe.send("Shutdown")

def send_task(id, pipe, prog, rr_result_cache, rr_result_file):
    while True:
        if q.empty():
            continue
        line = q.get()
        print("[sender][" + str(id) + "] Getting key " + line, flush=True)
        if line.startswith("FIN"):
            break
        pending_count_lock.acquire()
        global pending_count
        pending_count_local = pending_count
        pending_count_lock.release()
        print("[sender][" + str(id) + "] pending count is: " + str(pending_count_local))
        if pending_count_local <= num_processor:
            restart_static_slicing_local = False
            restart_static_slicing_lock.acquire()
            global restart_static_slicing
            if restart_static_slicing == True:
                restart_static_slicing_local = True
                restart_static_slicing = False
            restart_static_slicing_lock.release()
            if restart_static_slicing_local is True:
                rr_result_cache_lock.acquire()
                json.dump(rr_result_cache, open(rr_result_file, 'w'), indent=4)
                rr_result_cache_lock.release()

                it_lock.acquire()
                global it
                it += 1
                it_local = it
                it_lock.release()
                print("[sender][" + str(id) + "] Execution of static slicing pass {} starts at {}".format(it_local,\
                    datetime.datetime.strftime(datetime.datetime.now(), "%Y/%m/%d, %H:%M:%S")), flush=True)
                os.system('python3 static_dep_graph.py --parallelize_rr >> out{} &'.format(it_local))

        if line.startswith(prog):
            line = line[len(prog):]
        segs = line.split('_')
        a0 = None if segs[0].strip() == "None" else segs[0].strip()  # This is expected, a0 is empty string
        a1 = None if segs[1].strip() == "None" else segs[1].strip()
        a2 = None if segs[2].strip() == "None" else segs[2].strip()
        a3 = None if segs[3].strip() == "None" else segs[3].strip()
        a4 = None if segs[4].strip() == "None" else segs[4].strip()
        a5 = None if segs[5].strip() == "None" else segs[5].strip()
        a6 = None if segs[6].strip() == "None" else segs[6].strip()
        a7 = None if segs[7].strip() == "None" else segs[7].strip()
        print("[sender][" + str(id) + "] Sending task {}".format(line), flush=True)
        pipe.send((prog, a1, a2, a3, a4, a5, a6, a7))
        print("[sender][" + str(id) + "] Sent task {}".format(line), flush=True)
        result_cache = pipe.recv()
        print("[sender][" + str(id) + "] Receiving result for task {}".format(line), flush=True)
        rr_result_cache_lock.acquire()
        for key, value in result_cache.items():
            rr_result_cache[key] = value
        rr_result_cache_lock.release()
        pending_count_lock.acquire()
        pending_count -= 1
        pending_count_lock.release()
    print("[sender][" + str(id) + "] Thread finishing execution.", flush=True)
    pipe.send("Shutdown")
    while pipe.recv() != "Shutdown":
        pipe.send("Shutdown")
    print("[sender][" + str(id) + "] Thread finished execution.", flush=True)

def main():
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    prog = '909_ziptest_exe9'
    if len(sys.argv) > 1:
        prog = sys.argv[1]
    rr_result_file = os.path.join(curr_dir, 'cache', prog, 'rr_results_{}.json'.format(prog))
    print("Setting up parallel environment")
    for iter in range(num_processor):
        process_dir = os.path.join(curr_dir, 'run_{}'.format(iter))
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

    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
    try:
        server_t = threading.Thread(target=server_thread, args=(server))
        server_t.start()
    except:
        print("Error: unable to start thread")

    print("Starting execution")
    mp.set_start_method('spawn')

    start_time = datetime.datetime.now()
    print("Execution of static slicing pass 0 starts at {}".format( \
        datetime.datetime.strftime(start_time, "%Y/%m/%d, %H:%M:%S")), flush=True)
    os.system('python3 static_dep_graph.py --parallelize_rr >> out0 &')
    global rr_result_cache
    if os.path.exists(rr_result_file):
        with open(rr_result_file) as file:
            rr_result_cache = json.load(file)

    processes = []
    threads = []
    try:
        for j in range(num_processor):
            parent_conn, child_conn = mp.Pipe(duplex=True)
            p = mp.Process(target = run_task, args=(j, child_conn, prog))
            p.start()
            processes.append(p)
            t = threading.Thread(target=send_task, args=(j, parent_conn, prog, rr_result_cache, rr_result_file))
            t.start()
            threads.append(t)

        for j in range(num_processor):
            processes[j].join()
            threads[j].join()
    except Exception as e:
        print("Running parallelized RR failed")
        print(str(e))
        print("-" * 60)
        traceback.print_exc(file=sys.stdout)
        print("-" * 60)
    except KeyboardInterrupt:
        print('Interrupted')

    json.dump(rr_result_cache, open(rr_result_file, 'w'), indent=4)

    it_lock.acquire()
    global it
    it += 1
    it_local = it
    it_lock.release()
    print("Execution of static slicing pass {} starts at {}".format(it_local, \
            datetime.datetime.strftime(datetime.datetime.now(), "%Y/%m/%d, %H:%M:%S")), flush=True)
    os.system('python3 static_dep_graph.py >> out{}'.format(it_local))

    server.shutdown()
    server_t.join()
    server.server_close()
    duration = datetime.datetime.now() - start_time
    print("Running static slicing with parallized RR took {} ".format(duration))

if __name__ == '__main__':
    main()
