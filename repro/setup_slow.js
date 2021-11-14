
(function setup() {
    db.dropDatabase();

    const key = 'value';
    const DOCS = 10 * 50000;
    for (let i = 0; i < DOCS / 50000; i++) {
        let bulk = db.coll.initializeUnorderedBulkOp();
        for (let j = 0; j < 50000; j++) {
            let val = i * 50000 + j;
                bulk.insert({a: key, b: val, c: val})
            }
        bulk.execute();
    }

    db.coll.createIndex({a: 1, b:1});
    db.coll.createIndex({a: 1, c:1});
}) ();
