/**

 * Reproduces inconsistent delete performance with secondary indexes.

 * Notably, deletes on collections with multiple secondary indexes have significantly

 * worse performance than deletes with one index or deletes that hint a specific index.

 */

(function() {

 

const time = (fn, desc) => {

    print("starting " + desc);

    let start = new Date();

    fn();

    let end = new Date();

    print(desc + ": " + (end - start) + "ms");

};

 

const key = 'value';

const bulkLoad = (coll) => {

    coll.drop();

    const DOCS = 10 * 1000;

    for (let i = 0; i < DOCS / 1000; i++) {

        let bulk = coll.initializeUnorderedBulkOp();

        for (let j = 0; j < 1000; j++) {

            let val = i * 1000 + j;

            // a is not unique, b is

            bulk.insert({a: key, b: val, c: val});

        }

        assert.commandWorked(bulk.execute());

    }

    print("inserted " + DOCS);

};

 

const testColl = db.coll;

(function remove1() {

    bulkLoad(testColl);

    assert.commandWorked(testColl.createIndex({a: 1, b: 1}));

 

    time(() => {

        assert.commandWorked(

            db.runCommand({delete: testColl.getName(), deletes: [{q: {a: key}, limit: 0}]}));

    }, "remove with 1 index");

})();

 

(function remove2() {

    bulkLoad(testColl);

    assert.commandWorked(testColl.createIndex({a: 1, b: 1}));

    assert.commandWorked(testColl.createIndex({a: 1, c: 1}));

 

    time(() => {

        assert.commandWorked(

            db.runCommand({delete: testColl.getName(), deletes: [{q: {a: key}, limit: 0}]}));

    }, "remove with 2 indexes");

})();

 

(function remove2Hint() {

    bulkLoad(testColl);

    assert.commandWorked(testColl.createIndex({a: 1, b: 1}));

    assert.commandWorked(testColl.createIndex({a: 1, c: 1}));

 

    time(() => {

        assert.commandWorked(db.runCommand(

            {delete: testColl.getName(), deletes: [{q: {a: key}, limit: 0, hint: 'a_1_b_1'}]}));

    }, "remove with 2 indexes and a hint");

})();

})();

