(function remove() {
    db.runCommand({delete: db.coll.getName(), deletes: [{q: {a: 'value'}, limit: 0, hint: 'a_1_b_1'}]});
}) ();
