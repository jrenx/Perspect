import os
import sys
import multiprocessing

import pymongo
from pymongo import MongoClient

# Clean up and start mongo server
def start(mongo_dir="~/mongoDB/4.2.1"):
    db = mongo_dir + "/db"
    os.system("sudo rm -rf {}".format(db))
    os.system("mkdir -p {}".format(db))
    mongod = mongo_dir + "/bin/mongod"
    log = mongo_dir + "/db.log"
    os.system("sudo {} --dbpath {} --logpath {} --wiredTigerCacheSizeGB 10 --fork".format(mongod, db, log))

# Create indexes
def createIndex():
    client = MongoClient()
    db = client['database']
    for b in range(10):
        spec = [('x', pymongo.ASCENDING), ('a', pymongo.ASCENDING),
            ('_id', pymongo.ASCENDING), ('b{}'.format(b), pymongo.ASCENDING)]
        db['c0'].create_index(spec, unique=False)
        db['c1'].create_index(spec, unique=False)
        db['c2'].create_index(spec, unique=False)
        db['c3'].create_index(spec, unique=False)
        db['c4'].create_index(spec, unique=False)

# Insert entries
def insert(idd):
    size = 20
    count = 1000 * 100
    every = 1000
    x = 'x' * size

    client = MongoClient()
    db = client['database']
    c = db['c{}'.format(idd)]

    many = []
    for i in range(count):
        if (i % every == 0):
            if (i > 0):
                c.insert_many(many)
            many = []
        doc = {'_id': i, 'x': x, 'b0': 0, 'b1': 0, 'b2': 0, 'b3': 0, 'b4': 0,
            'b5': 0, 'b6': 0, 'b7': 0, 'b8': 0, 'b9': 0, 'a': 0}
        many.append(doc)

if __name__ == '__main__':
    #if len(sys.argv) == 2:
    #    start(sys.argv[1])
    #else:
    #    start()
    
    createIndex()

    nthreads = 10
    threads = []
    for i in range(nthreads):
        t = multiprocessing.Process(target=insert, args=(i, ))
        threads.append(t)
        t.start()
    for i in range(nthreads):
        threads[i].join()
