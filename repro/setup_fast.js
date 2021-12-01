
(function setup() {
    db.dropDatabase();

    const DOCS = 10 * 100;
    for (let i = 0; i < DOCS / 100; i++) {
        let bulk = db.coll.initializeUnorderedBulkOp();
        for (let j = 0; j < 100; j++) {
            let val = i * 100 + j;
                bulk.insert({t: new Date()})
            }
        bulk.execute();
    }

}) ();
