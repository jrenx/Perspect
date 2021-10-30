import os
import sys
import multiprocessing
import time
import pymongo
from pymongo import MongoClient
import json
# start mongo server
def start(mongo_dir="~/mongoDB/4.2.1"):
    db = mongo_dir + "/db"
    mongod = mongo_dir + "/bin/mongod"
    log = mongo_dir + "/db.log"
    os.system("{} --dbpath {} --logpath {} --wiredTigerCacheSizeGB 10 --fork".format(mongod, db, log))

def update(idd):
    mod = 1000
    
    client = MongoClient()
    db = client['database']
    #print(db.command("dbstats"))
    #s = db.command("collstats", "c"+str(i))
    #print(s)
    c = db['c{}'.format(idd)]
    a = time.time()
    for i in range(1):
        c.update_many({'_id': {'$mod': [mod, i % mod]}}, {'$inc': {'a': 1}})    
    b = time.time()
    print("Took " + str(b-a))

if __name__ == '__main__':

    nthreads = 5
    threads = []
    time.sleep(120)
    print("Starting test...")
    for i in range(nthreads):
        t = multiprocessing.Process(target=update, args=(i,))
        threads.append(t)
        t.start()
    for i in range(nthreads):
        threads[i].join()
    os.system("kill -3 3257")
