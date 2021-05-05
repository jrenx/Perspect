import sys
import json
import os
import subprocess
curr_dir = os.path.dirname(os.path.realpath(__file__))

def run():
    c = int(sys.argv[1])
    folder = sys.argv[2]
    rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    for i in range(0,16):
        f1 = os.path.join(curr_dir, folder + "_" + str(i), "cache", "rr_results_" + str(i) + ".json")
        f2 = os.path.join(curr_dir, folder + "_" + str(i), "cache", "rr_results_" + str(i) + "_" + str(c) + ".json")
        subprocess.run(["mv", f1, f2])
        f1 = os.path.join(curr_dir, folder + "_" + str(i), "out")
        f2 = os.path.join(curr_dir, folder + "_" + str(i), "out" + str(c))
        subprocess.run(["mv", f1, f2])
    subprocess.run(["mv", "rr_inputs", "rr_inputs" + str(c)])
 
if __name__ == "__main__":
    run()
