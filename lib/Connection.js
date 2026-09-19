const WebSocketClient = require('websocket').client;

const MessageHeader = require('./Message/Header.js');
const MessageText = require('./Message/Text.js');
const MessageFile = require('./Message/File.js');
const MessageEventValue = require('./Message/EventValue.js');
const MessageEventText = require('./Message/EventText.js');
const MessageEventDaytimer = require('./Message/EventDaytimer.js');
const MessageEventWeather = require('./Message/EventWeather.js');

/*
    Events:
        close
        close_failed
        connect
        connect_failed
        connection_error
        send
        message_header
        message_text
        message_file
        message_event_table_values
        message_event_table_text
        message_event_table_daytimer
        message_event_table_weather
        message_invalid
        keepalive
*/

var Connection = function (host, keepalive) {
    this._host = host;
    this._keepalive = (keepalive === undefined ? 30000 : keepalive);
    this._keepalive_interval = undefined;
    this._keepalive_time = undefined;
    this._reconnect_interval = undefined;
    this._ws_url = 'wss://' + host + '/ws/rfc6455';
    this._ws = {
        'client': new WebSocketClient(),
        'connection': undefined,
    };
    this._closed = false;
    this._pending_files = [];
    this._connection_data = { message_state: 'header' };
    this.register_client();
};

Connection.prototype.__proto__ = require('events').EventEmitter.prototype;

Connection.prototype.connect = function () {
    if (this._closed) return;
    this._ws.client.connect(this._ws_url, 'remotecontrol');
};

Connection.prototype._clear_timers = function () {
    clearInterval(this._keepalive_interval);
    clearInterval(this._reconnect_interval);
    this._keepalive_interval = undefined;
    this._reconnect_interval = undefined;
    this._keepalive_sent = undefined;
};

Connection.prototype.close = function (silent) {
    var wasClosed = this._closed;
    this._closed = true;
    this._clear_timers();
    this._pending_files = [];
    var connection = this._ws.connection;
    this._ws.connection = undefined;
    if (connection) {
        connection.close();
    } else if (typeof this._ws.client.abort === 'function') {
        this._ws.client.abort();
    }
    if (!wasClosed && !silent) this.emit('close', false, 'closed');
};

Connection.prototype.register_client = function () {
    var that = this;
    this._ws.client.on('connectFailed', function (error) {
        if (!that._closed) that.emit('connect_failed', error, error.message);
    });
    this._ws.client.on('connect', function (connection) {
        if (that._closed) {
            connection.close();
            return;
        }
        that.register_connection(connection);
        that.emit('connect');
    });
};

Connection.prototype.register_connection = function (connection) {
    var that = this;
    this._clear_timers();
    this._closed = false;
    this._ws.connection = connection;
    this._pending_files = [];
    this._connection_data = { message_state: 'header' };
    this._keepalive_interval = setInterval(function () {
        if (that._ws.connection && that._keepalive_sent === undefined) {
            that._keepalive_sent = Date.now();
            that._ws.connection.sendUTF('keepalive');
        }
    }, this._keepalive);
    this._reconnect_interval = setInterval(function () {
        if (that._keepalive_sent !== undefined &&
            Date.now() - that._keepalive_sent > Number(that._keepalive) + 2000) {
            that.close(true);
            that.emit('close', true, 'timeout');
        }
    }, 500);
    connection.on('close', function (code, description) {
        if (that._closed) return;
        var outOfService = that._connection_data.last_header &&
            that._connection_data.last_header.identifier === 5;
        that._closed = true;
        that._ws.connection = undefined;
        that._pending_files = [];
        that._clear_timers();
        that.emit('close', Boolean(outOfService), description + ' (' + code + ')');
    });
    connection.on('error', function (error) {
        if (that._closed) return;
        that.close(true);
        that.emit('connection_error', error, error.message);
    });
    connection.on('message', function (message) {
        if (!that._closed) that.handle_message(message);
    });
};

Connection.prototype._send = function (message) {
    this._connection_data.last_request = message;
    this._ws.connection.sendUTF(message);
    this.emit('send', message);
};

Connection.prototype.send = function (message, filename) {
    if (!this._ws.connection) return;
    // File replies have no request ID. Serialize files while allowing control
    // commands and their identifiable replies to pass independently.
    if (!filename && /\.[a-z0-9]+(?:\?.*)?$/i.test(message) &&
        !/^(?:j?dev\/|authenticate)/.test(message)) filename = message;
    if (filename) {
        this._pending_files.push({ message: message, filename: filename });
        if (this._pending_files.length > 1) return;
    }
    this._send(message);
};

Connection.prototype.handle_message = function (message) {
    this.emit('handle_message', message);
    var result;
    try {
        result = this._decode_message(message);
    } catch (error) {
        // Close on malformed frames: guessing the next state could pair a file
        // or command with the wrong response. Application listeners are outside
        // this catch so their exceptions are not mislabeled as protocol errors.
        this.close(true);
        this.emit('message_invalid', message);
        this.emit('close', false, 'invalid message');
        return;
    }
    var nextFile;
    if (result.fileDone) {
        this._pending_files.shift();
        nextFile = this._pending_files[0];
    }
    try {
        if (result.keepalive !== undefined) this.emit('keepalive', result.keepalive);
        this.emit(result.event, result.value);
    } finally {
        if (nextFile && this._ws.connection && this._pending_files[0] === nextFile) {
            this._send(nextFile.message);
        }
    }
};

Connection.prototype._decode_message = function (message) {
    var state = this._connection_data.message_state;
    if (state === 'header') {
        if (message.type !== 'binary') throw new Error('Expected binary header');
        var header = new MessageHeader(message.binaryData);
        this._connection_data.last_header = header;
        this._connection_data.message_state = header.next_state();
        var result = { event: 'message_header', value: header };
        if (header.identifier === 6) {
            var now = Date.now();
            result.keepalive = this._keepalive_sent === undefined ? 0 : now - this._keepalive_sent;
            this._keepalive_time = new Date(now);
            this._keepalive_sent = undefined;
        }
        return result;
    }
    var length = message.type === 'binary' ? message.binaryData.length
        : Buffer.byteLength(message.utf8Data, 'utf8');
    if (length !== this._connection_data.last_header.len) throw new Error('Invalid payload length');
    var pending = this._pending_files[0];
    var result;
    if (state === 'text') {
        if (message.type !== 'utf8') throw new Error('Expected text payload');
        var text = new MessageText(message.utf8Data);
        if (text.type !== 'control' && pending) {
            result = { event: 'message_file', value: new MessageFile(message, pending.filename), fileDone: true };
        } else {
            result = { event: 'message_text', value: text,
                fileDone: Boolean(pending && text.control === pending.filename) };
        }
    } else if (state === 'binary_file') {
        if (message.type !== 'binary') throw new Error('Expected binary file');
        result = { event: 'message_file',
            value: new MessageFile(message, pending && pending.filename), fileDone: Boolean(pending) };
    } else {
        if (message.type !== 'binary') throw new Error('Expected binary event table');
        var parsers = {
            etable_values: MessageEventValue,
            etable_text: MessageEventText,
            etable_daytimer: MessageEventDaytimer,
            etable_weather: MessageEventWeather
        };
        var Parser = parsers[state];
        if (!Parser) throw new Error('Unknown message state');
        var events = [];
        for (var offset = 0; offset < length;) {
            var item = new Parser(message.binaryData, offset);
            if (item.data_length <= 0 || item.data_length > length - offset) {
                throw new Error('Invalid event length');
            }
            events.push(item);
            offset += item.data_length;
        }
        result = { event: 'message_event_table_' + state.substr(7), value: events };
    }
    this._connection_data.message_state = 'header';
    return result;
};

module.exports = Connection;
