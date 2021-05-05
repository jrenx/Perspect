import sys
import json
import os
curr_dir = os.path.dirname(os.path.realpath(__file__))

def remove_prefix(text, prefix):
        return text[text.startswith(prefix) and len(prefix):]

def run():
    folder = sys.argv[1]
    src = sys.argv[2]
    prog = sys.argv[3]
    rr_result_cache = {}
    rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    for i in range(0,16):
        curr_rr_result_file = os.path.join(curr_dir, folder + "_" + str(i), "cache", "rr_results_" + str(i) + ".json")
        if os.path.exists(curr_rr_result_file):
            with open(curr_rr_result_file, "r") as f:
                rr_result_cache.update(json.load(f))
                print(i)
                print(len(rr_result_cache))
        else:
            print("RR file not present at " + str(i))

    rr_src_result_file = os.path.join(src, "cache", "rr_results_" + prog + ".json")
    if os.path.exists(rr_src_result_file):
        with open(rr_src_result_file, "r") as f:
            rr_result_cache.update(json.load(f))
            print(len(rr_result_cache))
    else:
        print("Source RR file does not exist")
   
    print("Persisting rr result file")
    with open(rr_result_file, 'w') as f:
        json.dump(rr_result_cache, f, indent=4)
 
if __name__ == "__main__":
    run()
