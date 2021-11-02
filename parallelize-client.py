from json.decoder import JSONDecodeError
import sys
import os
import socket
import select
import json
import datetime
import time
import socketserver
import queue
import threading
import traceback

HOST, PORT = "localhost", 9999
q = queue.Queue()
DEBUG = True
num_server = 4
num_processor = 16

num_new_unique_inputs_received = 0
handled = set()

pending_count_lock = threading.Lock()
pending_count = 0

restart_static_slicing_lock = threading.Lock()
restart_static_slicing = False

rr_result_cache_lock = threading.Lock()
curr_dir = os.path.dirname(os.path.realpath(__file__))
rr_result_cache = {}
prog = '909_ziptest_exe9'
if __name__ == '__main__':
    if len(sys.argv) > 1:
        prog = sys.argv[1]
rr_result_file = os.path.join(curr_dir, 'cache', prog, 'rr_results_{}.json'.format(prog))
# for rr_result_cache

it_lock = threading.Lock()
it = 0
 
class MyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
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
                        os.system('python3.7 static_dep_graph.py --parallelize_rr > out{} 2>&1 &'.format(it_local))
                    else:
                        restart_static_slicing_lock.acquire()
                        global restart_static_slicing
                        restart_static_slicing = True
                        restart_static_slicing_lock.release()

                else:
                    print("[main receiver] Did not receive any new unique inputs, finish now...")
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
        except Exception as e:
            print("Caught exception in server handler: " + str(e))
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)

def server_thread(server):
        server.serve_forever()

def main():

    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
    server_t = threading.Thread(target=server_thread, args=(server, ))
    server_t.start()

    print("[client] Starting execution", flush=True)

    try:
        start_time = datetime.datetime.now()
        print("Execution of static slicing pass 0 starts at {}".format( \
            datetime.datetime.strftime(start_time, "%Y/%m/%d, %H:%M:%S")), flush=True)
        os.system('python3.7 static_dep_graph.py --parallelize_rr > out0 2>&1 &')
        if os.path.exists(rr_result_file):
            with open(rr_result_file) as f:
                rr_result_cache_lock.acquire()
                global rr_result_cache
                rr_result_cache = json.load(f)
                rr_result_cache_lock.release()

        start_time = datetime.datetime.now()
        print("[client] Execution of iteration 0 starts at {}".format(datetime.datetime.strftime(start_time, "%Y/%m/%d, %H:%M:%S")), flush=True)

        sockets = []
        port = 12000
        worker_addresses = []
        with open("servers.config", "r") as f:
            for l in f.readlines:
                worker_addresses.append((l.strip(), port))
 
        for addr in worker_addresses:
            for _ in range(num_processor):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print("[client] Connecting to {}".format(addr), flush=True)
                s.connect(addr)
                print("[client] Connected to {}".format(addr), flush=True)
                sockets.append(s)

        print("[client] Sending initial tasks", flush=True)
        closed_sockets = set()
        for s in sockets:
            while q.empty():
                continue
            line = q.get()

            if line.startswith("FIN"):
                print("[client] Received FIN from static dep graph", flush=True)
                s.close()
                q.put(line)
                closed_sockets.add(s)
                continue

            print("[client] Getting key " + line, flush=True)
            print("[client] Sending task {}".format(line), flush=True)
            s.send(line.encode())
            print("[client] Sent task {}".format(line), flush=True)
        sockets = [s for s in sockets if s not in closed_sockets]

        print("[client] Waiting for rr results", flush=True)
        while len(sockets) > 0:
            read_sockets, _, _ = select.select(sockets, [], [])

            for s in read_sockets:
                # Parse results
                chunks = []
                while True:
                    chunks.append(s.recv(4096))
                    ret = b''.join(chunks).decode()
                    if ret == "":
                        break
                    try:
                        json.loads(ret)
                    except JSONDecodeError:
                        continue
                    break
                ret = b''.join(chunks).decode()
                if ret == "": # Server should not close the socket. Only for precaution
                    s.close()
                    sockets.remove(s)
                    continue
                ret = json.loads(ret)
                print("[client] Receiving result for task {}".format(list(ret.keys())[0] if (len(ret) > 0) else ""), flush=True)
                #print("[client] Saving result to cache in memory")
                rr_result_cache_lock.acquire()
                #print("[client] Get rr result cache lock")
                for (key, value) in ret.items():
                    #print("Putting {} reuslt into rr cache".format(key))
                    rr_result_cache[key] = value
                    #print("Put {} result into rr cache".format(key))
                #print("[client] Releasing rr result cache lock")
                rr_result_cache_lock.release()
                #print("[client] Decreasing pending count")

                pending_count_lock.acquire()
                global pending_count
                pending_count -= 1
                pending_count_local = pending_count
                pending_count_lock.release()

                #print("[client] Decreased pending count")
                print("[client] pending count is: " + str(pending_count_local))
                if pending_count_local <= (num_processor * num_server):

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

                        print("[client] Execution of static slicing pass {} starts at {}".format(it_local,\
                            datetime.datetime.strftime(datetime.datetime.now(), "%Y/%m/%d, %H:%M:%S")), flush=True)
                        os.system('python3.7 static_dep_graph.py --parallelize_rr > out{} 2>&1 &'.format(it_local))

                # Send new task if availble
                #print("[client] Waiting for task")
                while q.empty():
                    continue
                line = q.get()
                print("[client] Get task {}".format(line))
                if line.startswith("FIN"):
                    print("[client] Received FIN from static dep graph", flush=True)
                    s.close()
                    q.put(line)
                    sockets.remove(s)
                    break

                print("[client] Getting key " + line, flush=True)
                print("[client] Sending task {}".format(line), flush=True)
                s.send(line.encode())
                print("[client] Sent task {}".format(line), flush=True)
    except Exception as e:
        print("Caught exception in main loop: " + str(e))
        print(str(e))
        print("-" * 60)
        traceback.print_exc(file=sys.stdout)
        print("-" * 60)
    json.dump(rr_result_cache, open(rr_result_file, 'w'), indent=4)
    it_lock.acquire()
    it += 1
    it_local = it
    it_lock.release()
    print("[client] Execution of static slicing pass {} starts at {}".format(it_local, \
            datetime.datetime.strftime(datetime.datetime.now(), "%Y/%m/%d, %H:%M:%S")), flush=True)
    os.system('python3.7 static_dep_graph.py > out{} 2>&1'.format(it_local))

    server.shutdown()
    server_t.join()
    server.server_close()
    duration = datetime.datetime.now() - start_time
    print("[client] Running uses {} seconds".format(duration))

if __name__ == '__main__':
    main()
