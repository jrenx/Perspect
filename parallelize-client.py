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

#worker_addresses = [("10.1.0.21", 12000), ("10.1.0.24", 12000)]
worker_addresses = [("10.1.0.21", 12000)]

HOST, PORT = "localhost", 9999
q = queue.Queue()
DEBUG = True
num_processor = 16

class MyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        self.data = self.rfile.readline().strip().decode("utf-8")
        q.put(self.data)
        #print("{} wrote:".format(self.client_address[0]))
        print(self.data)

def server_thread():
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()

def main():
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    prog = '909_ziptest_exe9'
    if len(sys.argv) > 1:
        prog = sys.argv[1]
    rr_result_file = os.path.join(curr_dir, 'cache', prog, 'rr_results_{}.json'.format(prog))
    rr_result_cache = {}
    handled = set()

    server_t = threading.Thread(target=server_thread, args=())
    server_t.start()

    print("[client] Starting execution", flush=True)
    for i in range(5):
        print("In iteration {}".format(i), flush=True)
        start_time = datetime.datetime.now()
        os.system('python3 static_dep_graph.py >> out' + str(i) + ' &')
        if os.path.exists(rr_result_file):
            with open(rr_result_file) as f:
                rr_result_cache = json.load(f)
 
        start_time = datetime.datetime.now()
        print("[client] Execution of itertaion {} starts at {}".format(i, datetime.datetime.strftime(start_time, "%Y/%m/%d, %H:%M:%S")), flush=True)

        sockets = []
        for addr in worker_addresses:
            print("[client] Connecting to {}".format(addr), flush=True)
            for _ in range(16):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(addr)
                sockets.append(s)

        print("[client] Sending initial tasks", flush=True)
        closed_sockets = set()
        for s in sockets:
            while True:
                print("[client] Waiting for static dep graph results", flush=True)
                while q.empty():
                    continue
                print("[client] Getting result from static dep graph", flush=True)
                line = q.get()
                print("[client] Result from static dep graph {}".format(line), flush=True)

                if line.strip().startswith("FIN"):
                    print("[client] Received FIN from static dep graph", flush=True)
                    q.put(line)
                    s.close()
                    closed_sockets.add(s)
                    break

                if line not in handled:
                    handled.add(line)
                    print("[client] Getting key " + line, flush=True)
                    print("[client] Sending task {}".format(line), flush=True)
                    s.send(line.encode())
                    print("[client] Sent task {}".format(line), flush=True)
                    break
        sockets = [s for s in sockets if s not in closed_sockets]

        print("[client] Waiting for rr results", flush=True)
        while len(sockets) > 0:
            read_sockets, _, _ = select.select(sockets, [], [])

            for s in read_sockets:
                # Parse results
                ret = s.recv(4096).decode()
                if ret == "": # Server should not close the socket. Only for precaution
                    s.close()
                    sockets.remove(s)
                    continue
                print("[client] Receiving result for task {}".format(line), flush=True)
                ret = json.loads(ret)
                for (key, value) in ret.items():
                    rr_result_cache[key] = value
                
                # Send new task if availble
                while True:
                    while q.empty():
                        continue
                    line = q.get()

                    if line.strip().startswith("FIN"):
                        print("[client] Received FIN from static dep graph", flush=True)
                        q.put(line)
                        s.close()
                        socekts.remove(s)
                        break

                    if line not in handled:
                        handled.add(line)
                        print("[client] Getting key " + line, flush=True)
                        print("[client] Sending task {}".format(line), flush=True)
                        s.send(line.encode())
                        print("[client] Sent task {}".format(line), flush=True)
                        break

        json.dump(rr_result_cache, open(rr_result_file, 'w'), indent=4)

        duration = datetime.datetime.now() - start_time
        print("[client] Running iteration {} uses {} seconds".format(iter, duration))

if __name__ == '__main__':
    main()
