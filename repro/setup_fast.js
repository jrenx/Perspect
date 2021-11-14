
(function setup() {
    db.dropDatabase();

    const key = 'value';
    const DOCS = 10 * 500;
    for (let i = 0; i < DOCS / 500; i++) {
        let bulk = db.coll.initializeUnorderedBulkOp();
        for (let j = 0; j < 500; j++) {
            let val = i * 500 + j;
                bulk.insert({a: key, b: val, c: val})
            }
        bulk.execute();
    }

    db.coll.createIndex({a: 1, b:1});
    db.coll.createIndex({a: 1, c:1});
}) ();
