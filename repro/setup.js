
(function setup() {
    db.dropDatabase();

    const DOCS = 10 * 1000;
    for (let i = 0; i < DOCS / 1000; i++) {
        let bulk = db.coll.initializeUnorderedBulkOp();
        for (let j = 0; j < 1000; j++) {
            let val = i * 1000 + j;
                bulk.insert({t: new Date()})
            }
        bulk.execute();
    }

}) ();
