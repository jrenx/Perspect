(function() {
    db.adminCommand({setParameter: 1, ttlMonitorEnabled: false});
    db.coll.createIndex({t: -1}, {expireAfterSeconds: 0});
    db.adminCommand({setParameter: 1, ttlMonitorEnabled: true});
    const ttlPasses = db.serverStatus().metrics.ttl.passes;
    while (db.serverStatus().metrics.ttl.passes < ttlPasses + 2) {
        sleep(1000);
    }
    db.getSiblingDB("admin").shutdownServer();
}) ();
