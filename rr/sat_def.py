import json
import subprocess
import os


def run_break_points(breakpoints):
    json.dump({"breakpoints": breakpoints}, open('config.json', 'w'))
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate('source get_breakpoints'.encode(), 60 * 10)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        return False
    return True


if __name__ == '__main__':
    run_break_points(['mgc0.c:144', 'mgc0.c:150'])

