import sys
from rr_util import *
curr_dir = os.path.dirname(os.path.realpath(__file__))

def remove_prefix(text, prefix):
        return text[text.startswith(prefix) and len(prefix):]

def run():
    num = int(sys.argv[1])
    count = int(sys.argv[2])
    rr_result_cache = {}
    rr_result_file = os.path.join(curr_dir, 'cache', 'rr_results_' + str(num) +'.json')
    prog = sys.argv[3]
    with open("../rr_inputs", "r") as f:
        lines = f.readlines()
        incre = int(len(lines)/count)
        for i in range(num*incre, (num+1)*incre):
            line = lines[i]
            line = remove_prefix(line, prog)
            print("At index " + str(i) + " " + line)
            segs = line.split("_")
            a0 = None if segs[0].strip() == "None" else segs[0].strip()
            a1 = None if segs[1].strip() == "None" else segs[1].strip() 
            a2 = None if segs[2].strip() == "None" else segs[2].strip() 
            a3 = None if segs[3].strip() == "None" else segs[3].strip() 
            a4 = None if segs[4].strip() == "None" else segs[4].strip() 
            a5 = None if segs[5].strip() == "None" else segs[5].strip() 
            a6 = None if segs[6].strip() == "None" else segs[6].strip() 
            a7 = None if segs[7].strip() == "None" else segs[7].strip() 
            try:
                rr_backslice2(prog, a1, a2, a3, a4, a5, a6, a7, rr_result_cache)
            except Exception as e:
                print("FAILED at " + str(i) + " " + line)
                continue
    
    print("Persisting rr result file")
    with open(rr_result_file, 'w') as f:
        json.dump(rr_result_cache, f, indent=4)
 
if __name__ == "__main__":
    run()
