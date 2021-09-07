import sys
import os
import shutil
import multiprocessing as mp
import threading
import socket
import json
import datetime
import traceback

port = 12000

def run_task(id, pipe, prog):
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
        #print("[worker][{}] recive task {}".format(id, str_args),flush=True)
        print("Process {} recive task {}".format(id, str_args))
        rr_result_cache = {}
        start_time = datetime.datetime.now()
        try:
            rr_util.rr_backslice2(prog, a1, a2, a3, a4, a5, a6, a7, rr_result_cache)
        except Exception as e:
            print("[rr][" + pid + "][ERROR] Calling RR failed for input: " + str(str_args))
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)

        duraton = datetime.datetime.now() - start_time
        #print("[worker][{}] finish task {} in {}".format(id, str_args, duraton),flush=True)
        print("Process {} finish task {} in {}".format(id, str_args, duraton))
        pipe.send(rr_result_cache)
    #print("[worker][{}] finished execution.".format(id),flush=True)
    pipe.send("Shutdown")




def main():
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    num_processor = 16
    prog = '909_ziptest_exe9'
    if len(sys.argv) > 1:
        prog = sys.argv[1]

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


    processes = []
    pipes = []

    mp.set_start_method('spawn')
    for i in range(num_processor):
        parent_conn, child_conn = mp.Pipe(duplex=True)
        p = mp.Process(target = run_task, args=(i, child_conn, prog))
        p.start()
        processes.append(p)
        pipes.append(parent_conn)

    print("Setting up sockets")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((socket.gethostname(), port))
    listener.listen(16)



    while True:
        (client, addr) = listener.accept()
        print("Getting connection from {}".format(addr))

        def connect_bridge(socket, pipe):
            while True:
                line = socket.recv(4096).decode()
                print("Receive from socket: {}".format(line), flush=True)
                if line == "":
                    pipes.append(pipe)
                    return
                
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
                #print("[sender][" + str(id) + "] Sending task {}".format(line), flush=True)
                print("Send task {}".format(line), flush=True)
                pipe.send((prog, a1, a2, a3, a4, a5, a6, a7))
                #print("[sender][" + str(id) + "] Sent task {}".format(line), flush=True)

                ret = pipe.recv()
                #print("[sender][" + str(id) + "] Receiving result for task {}".format(line), flush=True)
                socket.send(json.dumps(ret).encode())


        if len(pipes) > 0:
            pipe = pipes.pop()
            threading.Thread(target=connect_bridge, args=(client, pipe)).start()


    for i in range(num_processor):
        processes[i].join()

if __name__ == '__main__':
    main()
