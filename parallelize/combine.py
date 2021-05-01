import sys
import json
import os
curr_dir = os.path.dirname(os.path.realpath(__file__))

def remove_prefix(text, prefix):
        return text[text.startswith(prefix) and len(prefix):]

def run():
    folder = int(sys.argv[1])
    src = int(sys.argv[2])
    prog = int(sys.argv[3])
    rr_result_cache = {}
    rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    for i in range(0,16):
        with open(os.path.join(curr_dir, folder + "_" + str(i), "cache", "rr_results_" + str(i) + ".json"), "r") as f:
            rr_result_cache.update(json.load(f))
            print(i)
            print(len(rr_result_cache))
    with open(os.path.join(src, "cache", r"r_results_909_" + prog + ".json"), "r") as f:
        rr_result_cache.update(json.load(f))
        print(len(rr_result_cache))
   
    print("Persisting rr result file")
    with open(rr_result_file, 'w') as f:
        json.dump(rr_result_cache, f, indent=4)
 
if __name__ == "__main__":
    run()
