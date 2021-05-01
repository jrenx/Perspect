import sys
import json
import os
curr_dir = os.path.dirname(os.path.realpath(__file__))

def remove_prefix(text, prefix):
        return text[text.startswith(prefix) and len(prefix):]

def run():
    rr_result_cache = {}
    rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    for i in range(0,16):
        with open("/home/anygroup/eval_909_32bit_rr_runs/eval_909_32bit-" + str(i)+ "/cache/rr_results_" + str(i) + ".json", "r") as f:
            rr_result_cache.update(json.load(f))
            print(i)
            print(len(rr_result_cache))
    with open("/home/anygroup/eval_909_32bit/cache/rr_results_909_ziptest_exe9_32.json", "r") as f:
        rr_result_cache.update(json.load(f))
        print(len(rr_result_cache))
   
    print("Persisting rr result file")
    with open(rr_result_file, 'w') as f:
        json.dump(rr_result_cache, f, indent=4)
 
if __name__ == "__main__":
    run()
