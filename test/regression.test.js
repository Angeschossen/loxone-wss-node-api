const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const https = require('node:https');
const http = require('node:http');
const crypto = require('node:crypto');
const API = require('../lib/API');
const Connection = require('../lib/Connection');
const JWT = require('../lib/Auth/JWT');
const TokenEnc = require('../lib/Auth/Token-Enc');
const AES = require('../lib/Auth/AES-256-CBC');
const UUID = require('../lib/Message/UUID');
const getText = require('../lib/Http');

function timers(t) {
    const active = new Map();
    function schedule(fn, delay) {
        const handle = { fn, delay };
        active.set(handle, handle);
        return handle;
    }
    t.mock.method(global, 'setTimeout', schedule);
    t.mock.method(global, 'setInterval', schedule);
    t.mock.method(global, 'clearTimeout', handle => active.delete(handle));
    t.mock.method(global, 'clearInterval', handle => active.delete(handle));
    return active;
}

function socket(t) {
    const active = timers(t);
    const connection = new Connection('example.invalid', 1000);
    const ws = new EventEmitter();
    const sent = [];
    ws.sendUTF = command => sent.push(command);
    ws.close = t.mock.fn(() => ws.emit('close', 1000, 'closed'));
    connection.register_connection(ws);
    t.after(() => connection.close());
    return { connection, ws, sent, active };
}

function frame(connection, identifier, data) {
    const header = Buffer.alloc(8);
    header[0] = 3;
    header[1] = identifier;
    header.writeUInt32LE(typeof data === 'string' ? Buffer.byteLength(data) : data.length, 4);
    connection.handle_message({ type: 'binary', binaryData: header });
    connection.handle_message(typeof data === 'string'
        ? { type: 'utf8', utf8Data: data } : { type: 'binary', binaryData: data });
}

function responseMock(t, transport = https) {
    const requests = [];
    t.mock.method(transport, 'get', (url, callback) => {
        const request = new EventEmitter();
        const response = new EventEmitter();
        request.url = url;
        request.setTimeout = t.mock.fn();
        request.destroy = t.mock.fn();
        response.destroy = t.mock.fn();
        response.statusCode = 200;
        requests.push({ request, response });
        callback(response);
        return request;
    });
    return requests;
}

test('package loads and constructs every authentication strategy without node-forge', () => {
    for (const security of ['Hash', 'AES-256-CBC', 'Token-Enc', 'JWT']) {
        const api = new API('example.invalid', 'test', 'secret', 2, 'tests', false, security);
        api.register_auth_object();
        assert.equal(typeof api._auth.authorize, 'function');
        api.clear_auth_chain();
    }
    assert.equal(require('../package.json').dependencies['node-forge'], undefined);
});

test('status subscription is sent once, including automatic authorization path', t => {
    const { connection, sent } = socket(t);
    const api = new API('example.invalid', 'test', 'secret', 2, 'tests', false, 'Hash', 1000, false, true);
    api.register_connection(connection);
    api.register_auth_object();
    api._auth.emit('authorized');
    api.enable_status_updates();
    assert.deepEqual(sent, ['jdev/sps/enablebinstatusupdate']);
});

test('failed handshake reports the supplied error and schedules one delayed retry', t => {
    const active = timers(t);
    const api = new API('example.invalid', 'test', 'secret', 2, 'tests', true);
    const connection = new Connection('example.invalid');
    api.register_connection(connection);
    const error = new Error('Connection refused');
    let received;
    api.on('connect_failed', (value, reason) => { received = [value, reason]; });
    connection._ws.client.emit('connectFailed', error);
    assert.deepEqual(received, [error, error.message]);
    assert.equal(active.size, 1);
    assert.equal([...active.values()][0].delay, 1000);
    api.abort();
    assert.equal(active.size, 0);
});

test('text structure files correlate correctly across interleaved command replies', t => {
    const { connection, sent } = socket(t);
    const api = new API('example.invalid', 'test', 'secret');
    api.register_connection(connection);
    api.register_LoxAPP3json_response();
    let structure;
    let control;
    api.on('get_structure_file', value => { structure = value; });
    api.on('message_text', value => { control = value.control; });
    api.send_command('data/LoxAPP3.json', false);
    api.send_command('jdev/sps/test', false);
    frame(connection, 0, JSON.stringify({ LL: { control: 'jdev/sps/test', Code: '200' } }));
    assert.equal(control, 'jdev/sps/test');
    assert.equal(structure, undefined);
    frame(connection, 0, JSON.stringify({ lastModified: 'test', controls: {} }));
    assert.deepEqual(structure, { lastModified: 'test', controls: {} });
    assert.equal(api.file_chain.length, 0);
    assert.deepEqual(sent, ['data/LoxAPP3.json', 'jdev/sps/test']);
});

test('file downloads are serialized and a callback can request the next file without duplication', t => {
    const { connection, sent } = socket(t);
    const files = [];
    connection.on('message_file', file => files.push(file));
    connection.send('first.svg');
    connection.send('second.png');
    assert.deepEqual(sent, ['first.svg']);
    frame(connection, 0, '<svg/>');
    assert.deepEqual(sent, ['first.svg', 'second.png']);
    connection.once('message_file', () => connection.send('third.svg'));
    frame(connection, 1, Buffer.from([1, 2, 3]));
    assert.deepEqual(sent, ['first.svg', 'second.png', 'third.svg']);
    assert.deepEqual(files.map(file => file.filename), ['first.svg', 'second.png']);
});

test('file error responses release the queue without consuming a file callback', t => {
    const { connection, sent } = socket(t);
    connection.send('missing.svg');
    connection.send('next.svg');
    let code;
    connection.on('message_text', text => { code = text.code; });
    frame(connection, 0, JSON.stringify({ LL: { control: 'missing.svg', Code: '404' } }));
    assert.equal(code, '404');
    assert.deepEqual(sent, ['missing.svg', 'next.svg']);
});

test('complete fragmented version response connects once; abort rejects late responses', t => {
    timers(t);
    const requests = responseMock(t);
    const api = new API('example.invalid', 'test', 'secret');
    const connection = new Connection('example.invalid');
    t.mock.method(connection, 'connect', () => {});
    api.register_connection(connection);
    api.perform_version_check(connection);
    const body = JSON.stringify({ LL: { value: "{'version':'17.0.0.0'}" } });
    requests[0].response.emit('data', Buffer.from(body.slice(0, 12)));
    requests[0].response.emit('data', Buffer.from(body.slice(12)));
    assert.equal(connection.connect.mock.callCount(), 0);
    requests[0].response.emit('end');
    assert.equal(connection.connect.mock.callCount(), 1);
    assert.equal(api._security, 'JWT');
    api.perform_version_check(connection);
    api.abort();
    assert.equal(requests[1].request.destroy.mock.callCount(), 1);
    requests[1].response.emit('data', Buffer.from(body));
    requests[1].response.emit('end');
    assert.equal(connection.connect.mock.callCount(), 1);
});

for (const failure of ['status', 'json', 'error', 'aborted']) {
    test('version check reports ' + failure + ' failure once', t => {
        timers(t);
        const requests = responseMock(t);
        const api = new API('example.invalid', 'test', 'secret');
        const connection = new Connection('example.invalid');
        t.mock.method(connection, 'connect', () => {});
        api.register_connection(connection);
        const errors = [];
        api.on('connect_failed', error => errors.push(error));
        api.perform_version_check(connection);
        const { request, response } = requests[0];
        if (failure === 'status') response.statusCode = 503;
        if (failure === 'json') response.emit('data', Buffer.from('{broken'));
        if (failure === 'error') request.emit('error', new Error('offline'));
        if (failure === 'aborted') response.emit('aborted');
        response.emit('end');
        assert.equal(errors.length, 1);
        assert.equal(api.connection, undefined);
        assert.equal(connection.connect.mock.callCount(), 0);
    });
}

test('HTTP helper preserves split UTF-8 bytes and handles response errors once', t => {
    const requests = responseMock(t);
    const replies = [];
    getText(https, 'https://example.invalid', (...args) => replies.push(args));
    const data = Buffer.from('ä');
    requests[0].response.emit('data', data.subarray(0, 1));
    requests[0].response.emit('data', data.subarray(1));
    requests[0].response.emit('end');
    requests[0].response.emit('error', new Error('late'));
    assert.deepEqual(replies, [[null, 'ä']]);
});

for (const [Auth, transport, method] of [[JWT, https, '_get_certificate'], [TokenEnc, http, '_get_public_key'], [AES, http, '_get_public_key']]) {
    test(Auth.name + ' assembles auth response before parsing and ignores disposed work', t => {
        const requests = responseMock(t, transport);
        const auth = Auth === JWT ? new Auth('example.invalid', 'u', 'p', 2, {}, {})
            : new Auth('example.invalid', 'u', 'p', {}, {});
        const parsed = [];
        t.mock.method(auth, '_parse_public_key', body => parsed.push(body));
        t.mock.method(auth, '_generate_session_key', () => {});
        auth[method]();
        requests[0].response.emit('data', Buffer.from('first'));
        requests[0].response.emit('data', Buffer.from('second'));
        assert.equal(parsed.length, 0);
        requests[0].response.emit('end');
        assert.deepEqual(parsed, ['firstsecond']);
        assert.equal(auth._generate_session_key.mock.callCount(), 1);
        auth[method]();
        auth.dispose();
        requests[1].response.emit('data', Buffer.from('late'));
        requests[1].response.emit('end');
        assert.equal(requests[1].request.destroy.mock.callCount(), 1);
        assert.equal(parsed.length, 1);
    });

    test(Auth.name + ' reports invalid public key without exchanging a session', t => {
        const requests = responseMock(t, transport);
        const auth = Auth === JWT ? new Auth('example.invalid', 'u', 'p', 2, {}, {})
            : new Auth('example.invalid', 'u', 'p', {}, {});
        const errors = [];
        auth.on('auth_failed', error => errors.push(error));
        t.mock.method(auth, '_generate_session_key', () => {});
        auth[method]();
        requests[0].response.emit('data', Buffer.from('invalid key'));
        requests[0].response.emit('end');
        assert.equal(errors.length, 1);
        assert.equal(auth._generate_session_key.mock.callCount(), 0);
        auth.dispose();
    });
}

test('JWT extracts the final certificate public key using built-in crypto', () => {
    const certs = require('node:tls').rootCertificates;
    const auth = new JWT('example.invalid', 'u', 'p', 2, {}, {});
    auth._parse_public_key(certs[0] + '\n' + certs[1]);
    const expected = new crypto.X509Certificate(certs[1]).publicKey.export({ type: 'pkcs1', format: 'pem' });
    assert.equal(auth._public_key.key, expected);
    auth.dispose();
});

test('abort cancels retries and guards an already queued timer callback', t => {
    const active = timers(t);
    const api = new API('example.invalid', 'u', 'p', 2, 'tests', true);
    api.reconnect();
    const callback = [...active.values()][0].fn;
    t.mock.method(api, 'connect', () => {});
    api.abort();
    callback();
    assert.equal(api.connect.mock.callCount(), 0);
    assert.equal(active.size, 0);
});

test('closed handshake rejects late connection and duplicate connect does not start a request', t => {
    timers(t);
    const requests = responseMock(t);
    const api = new API('example.invalid', 'u', 'p');
    api.connect();
    const connection = api.connection;
    api.connect();
    assert.equal(requests.length, 1);
    api.abort();
    const ws = { close: t.mock.fn() };
    connection._ws.client.emit('connect', ws);
    assert.equal(ws.close.mock.callCount(), 1);
    assert.equal(api.connection, undefined);
});

test('specific text/daytimer/weather subscriptions preserve generic payloads', t => {
    const { connection } = socket(t);
    const api = new API('example.invalid', 'u', 'p');
    api.register_connection(connection);
    for (const kind of ['text', 'daytimer', 'weather']) {
        const event = { uuid: { string: 'id' }, text: 'hello', entry: [] };
        let generic, specific;
        api.once('update_event_' + kind, (uuid, value) => { generic = value; });
        api.once('update_event_' + kind + '_id', value => { specific = value; });
        connection.emit('message_event_table_' + kind, [event]);
        assert.equal(specific, kind === 'text' ? 'hello' : event);
        assert.equal(specific, generic);
    }
});

test('UUID reads correct endian fields repeatedly without mutation or globals', () => {
    const buffer = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
    const copy = Buffer.from(buffer);
    assert.equal(new UUID(buffer, 0).string, '33221100-5544-7766-8899aabbccddeeff');
    assert.equal(new UUID(buffer, 0).string, '33221100-5544-7766-8899aabbccddeeff');
    assert.deepEqual(buffer, copy);
    assert.equal(Object.hasOwn(global, 't'), false);
});

test('nested one-time command and file callbacks cannot remove unrelated handlers', () => {
    const api = new API('example.invalid', 'u', 'p');
    const calls = [];
    api.file_chain.push({ file: /^a$/, onetime: true, callback: () => calls.push('file') });
    api.register_command_response({ control: /^other$/, onetime: true, callback: () => calls.push('other') });
    api.register_command_response({ control: /^outer$/, onetime: true, callback: () => {
        calls.push('outer');
        api._message_file({ filename: 'a' });
        api._message_text({ control: 'outer' });
    } });
    api._message_text({ control: 'outer' });
    api._message_text({ control: 'other' });
    assert.deepEqual(calls, ['outer', 'file', 'other']);
    assert.equal(api.command_chain.length, 0);
    assert.equal(api.file_chain.length, 0);
    assert.equal(Object.hasOwn(global, 'index'), false);
});

for (const Auth of [JWT, TokenEnc]) {
    test(Auth.name + ' cleanup cancels token refresh and rejects queued callbacks', t => {
        const active = timers(t);
        const send = t.mock.fn();
        const api = new API('example.invalid', 'u', 'p');
        const auth = Auth === JWT ? new Auth('example.invalid', 'u', 'p', 2, { send }, api)
            : new Auth('example.invalid', 'u', 'p', { send }, api);
        api._auth = auth;
        auth._token = { validUntil: (Date.now() - Date.UTC(2009, 0, 1)) / 1000 + 1200 };
        auth._token_management();
        const callback = [...active.values()][0].fn;
        api.clear_auth_chain();
        callback();
        assert.equal(active.size, 0);
        assert.equal(send.mock.callCount(), 0);
        assert.equal(api.command_chain.length, 0);
    });
}

test('keepalive measures round-trip time and detects silence before the first response', t => {
    const { connection, sent, active } = socket(t);
    let now = 10000;
    t.mock.method(Date, 'now', () => now);
    const sendTick = connection._keepalive_interval.fn;
    const watchdog = connection._reconnect_interval.fn;
    sendTick();
    now += 125;
    let latency;
    connection.on('keepalive', value => { latency = value; });
    const header = Buffer.from([3, 6, 0, 0, 0, 0, 0, 0]);
    connection.handle_message({ type: 'binary', binaryData: header });
    assert.equal(latency, 125);
    sendTick();
    now += 3001;
    let reason;
    connection.on('close', (out, value) => { reason = value; });
    watchdog();
    assert.equal(reason, 'timeout');
    assert.equal(active.size, 0);
    assert.deepEqual(sent, ['keepalive', 'keepalive']);
});

test('missing first keepalive response closes the connection', t => {
    const { connection, active } = socket(t);
    let now = 1000;
    t.mock.method(Date, 'now', () => now);
    connection._keepalive_interval.fn();
    now += 3001;
    connection._reconnect_interval.fn();
    assert.equal(connection._ws.connection, undefined);
    assert.equal(active.size, 0);
});

for (const event of ['close', 'reconnect']) {
    test('abort from a ' + event + ' listener stops retries without recursive events', t => {
        const active = timers(t);
        const api = new API('example.invalid', 'u', 'p', 2, 'tests', true);
        let calls = 0;
        api.on(event, () => { calls++; api.abort(); });
        api.reconnect();
        assert.equal(calls, 1);
        assert.equal(active.size, 0);
        assert.equal(api._abort, true);
    });
}

test('explicit connection close emits once and releases both timers', t => {
    const { connection, active } = socket(t);
    let closes = 0;
    connection.on('close', () => closes++);
    connection.close();
    connection.close();
    assert.equal(closes, 1);
    assert.equal(active.size, 0);
});

test('HTTP helper reads a real locally streamed response', async t => {
    const server = http.createServer((request, response) => {
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.write('{"value":');
        setImmediate(() => response.end('42}'));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const body = await new Promise((resolve, reject) => {
        getText(http, 'http://127.0.0.1:' + server.address().port, (error, data) => {
            if (error) reject(error);
            else resolve(data);
        });
    });
    assert.deepEqual(JSON.parse(body), { value: 42 });
});

test('valid daytimer and weather records preserve entry fields', t => {
    const { connection } = socket(t);
    const daytimer = Buffer.alloc(52);
    daytimer.writeDoubleLE(2.5, 16);
    daytimer.writeInt32LE(1, 24);
    daytimer.writeInt32LE(1, 28);
    daytimer.writeInt32LE(60, 32);
    daytimer.writeInt32LE(120, 36);
    daytimer.writeDoubleLE(3.5, 44);
    let data;
    connection.on('message_event_table_daytimer', value => { data = value; });
    frame(connection, 4, daytimer);
    assert.equal(data[0].defValue, 2.5);
    assert.deepEqual(data[0].entry[0], { mode: 1, from: 60, to: 120, needActivate: 0, value: 3.5 });
    const weather = Buffer.alloc(92);
    weather.writeUInt32LE(123, 16);
    weather.writeInt32LE(1, 20);
    weather.writeDoubleLE(22.5, 44);
    weather.writeDoubleLE(1013.25, 84);
    connection.on('message_event_table_weather', value => { data = value; });
    frame(connection, 7, weather);
    assert.equal(data[0].lastUpdate, 123);
    assert.equal(data[0].entry[0].temperature, 22.5);
    assert.equal(data[0].entry[0].barometricPressure, 1013.25);
});

test('transport errors clean up timers and cause API reconnect', t => {
    const { connection, ws, active } = socket(t);
    const api = new API('example.invalid', 'u', 'p', 2, 'tests', true);
    api.register_connection(connection);
    const error = new Error('broken transport');
    let received;
    api.on('connection_error', value => { received = value; });
    ws.emit('error', error);
    assert.equal(received, error);
    assert.equal(api.connection, undefined);
    assert.equal(active.size, 1);
    api.abort();
    assert.equal(active.size, 0);
});

test('valid tables decode multiple values and padded multibyte text', t => {
    const { connection } = socket(t);
    const values = Buffer.alloc(48);
    values.writeDoubleLE(12.5, 16);
    values.writeDoubleLE(-3, 40);
    let received;
    connection.on('message_event_table_values', data => { received = data; });
    frame(connection, 2, values);
    assert.deepEqual(received.map(item => item.value), [12.5, -3]);
    const text = Buffer.alloc(40);
    text.writeUInt32LE(2, 32);
    text.write('ä', 36);
    connection.on('message_event_table_text', data => { received = data; });
    frame(connection, 3, Buffer.concat([text, text]));
    assert.deepEqual(received.map(item => item.text), ['ä', 'ä']);
});

for (const [name, identifier, buffer] of [
    ['value', 2, Buffer.alloc(23)],
    ['text', 3, (() => { const b = Buffer.alloc(36); b.writeUInt32LE(100, 32); return b; })()],
    ['daytimer', 4, (() => { const b = Buffer.alloc(28); b.writeInt32LE(-1, 24); return b; })()],
    ['weather', 7, (() => { const b = Buffer.alloc(24); b.writeInt32LE(1000000, 20); return b; })()]
]) {
    test('malformed ' + name + ' table emits invalid and closes without partial events', t => {
        const { connection, active } = socket(t);
        let invalid = 0;
        connection.on('message_invalid', () => invalid++);
        frame(connection, identifier, buffer);
        assert.equal(invalid, 1);
        assert.equal(connection._ws.connection, undefined);
        assert.equal(active.size, 0);
    });
}

test('truncated header closes safely; application exceptions are not protocol failures', t => {
    const { connection } = socket(t);
    let invalid = 0;
    connection.on('message_invalid', () => invalid++);
    connection.handle_message({ type: 'binary', binaryData: Buffer.alloc(2) });
    assert.equal(invalid, 1);
    const other = new Connection('example.invalid');
    other.on('message_header', () => { throw new Error('listener failure'); });
    other.on('message_invalid', () => invalid++);
    assert.throws(() => other.handle_message({ type: 'binary', binaryData: Buffer.from([3, 6, 0, 0, 0, 0, 0, 0]) }), /listener failure/);
    assert.equal(invalid, 1);
});
