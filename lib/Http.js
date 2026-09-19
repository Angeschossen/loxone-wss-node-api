// Read one complete response. Callers own parsing and cancellation.
module.exports = function getText(transport, url, callback) {
    var finished = false;
    function done(error, body) {
        if (finished) return;
        finished = true;
        callback(error, body);
    }
    var request = transport.get(url, function (response) {
        var chunks = [];
        var size = 0;
        response.on('error', done);
        response.on('aborted', function () { done(new Error('HTTP response aborted')); });
        response.on('data', function (chunk) {
            if (finished) return;
            size += chunk.length;
            if (size > 4 * 1024 * 1024) {
                done(new Error('HTTP response exceeds 4 MiB'));
                response.destroy();
                return;
            }
            chunks.push(Buffer.from(chunk));
        });
        response.on('end', function () {
            if (response.statusCode !== 200) {
                done(new Error('HTTP status ' + response.statusCode));
            } else {
                done(null, Buffer.concat(chunks).toString('utf8'));
            }
        });
    });
    request.on('error', done);
    request.setTimeout(15000, function () {
        request.destroy(new Error('HTTP request timed out'));
    });
    return request;
};
