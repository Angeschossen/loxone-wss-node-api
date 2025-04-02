const crypto = require('crypto');
const Connection = require('./Connection.js');
const https = require('node:https');
const JWT = require('./Auth/JWT.js');

/*
    Events:
        auth_failed
        authorized
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
        get_structure_file
        update_event
*/

var API = function (host, username, password, permissions, info, reconnect, security, keepalive,
    request_structure_file, request_status_updates
) {
    this._host = host;
    this._username = username;
    this._password = password;
    this._permissions = permissions;
    this._info = info;
    this._request_structure_file = request_structure_file;
    this._request_status_updates = request_status_updates;
    this._reconnect = reconnect;
    this._reconnect_timeout = undefined;
    this._keepalive = (keepalive === undefined ? 30000 : keepalive);
    this._abort = false;
    this._security = security === undefined ? "Hash" : security;
    this._auth_class = require('./Auth/' + this._security + '.js');
    this.command_chain = [];
    this.file_chain = [];
    this._auth = undefined;
    this.connection = undefined;
};

API.prototype.__proto__ = require('events').EventEmitter.prototype;

API.prototype.connect = function () {
    var connection = new Connection(this._host, this._keepalive);
    this.register_connection(connection);
    this.perform_version_check(connection);
};

API.prototype.close = function () {
    if (this.connection !== undefined) {
        this.connection.close();
    } else {
        this.emit('close_failed');
    }
};

API.prototype.abort = function () {
    clearTimeout(this._reconnect_timeout);
    this._abort = true;
    this.close();
};

API.prototype.is_connected = function () {
    return this.connection !== undefined;
};

API.prototype.register_connection = function (connection) {
    var that = this;
    if (this.connection !== undefined) {
        that.emit('already_connected');
        return;
    }

    this.connection = connection;

    this.connection.on('info', function (message) {
        that.emit('info', message);
    });

    this.connection.on('close', function (info, reason) {
        that.emit('close', info, reason);
    });

    this.connection.on('close', that.reconnect.bind(this));
    this.connection.on('error', that.reconnect.bind(this));
    this.connection.on('connect_failed', that.reconnect.bind(this));

    this.connection.on('close_failed', function () {
        that.emit('close_failed');
    });

    this.connection.on('connect', function () {
        that.emit('connect');
        that._status_update_subscription = false;
        that.register_auth_object();
        that._auth.authorize();
    });

    this.connection.on('connect_failed', function (error, reason) {
        that.emit('connect_failed', error, reason);
    });

    this.connection.on('connection_error', function (error, reason) {
        that.emit('connection_error', error, reason);
    });

    this.connection.on('send', function (message) {
        that.emit('send', message);
    });

    this.connection.on('handle_message', function (message) {
        that.emit('handle_message', message);
    });

    this.connection.on('message_header', function (message) {
        that.emit('message_header', message);
    });

    this.connection.on('message_text', function (message) {
        that._message_text(message);
        that.emit('message_text', message);
    });

    this.connection.on('message_file', function (message) {
        that._message_file(message);
        that.emit('message_file', message);
    });

    this.connection.on('message_event_table_values', function (messages) {
        messages.forEach(function (evt) {
            that.emit('update_event_value', evt.uuid.string, evt.value);
            that.emit('update_event_value_' + evt.uuid.string, evt.value);
        });
        that.emit('message_event_table_values', messages);
    });

    this.connection.on('message_event_table_text', function (messages) {
        messages.forEach(function (evt) {
            that.emit('update_event_text', evt.uuid.string, evt.text);
            that.emit('update_event_text_' + evt.uuid.string, evt.value);
        });
        that.emit('message_event_table_text', messages);
    });

    this.connection.on('message_event_table_daytimer', function (messages) {
        messages.forEach(function (evt) {
            that.emit('update_event_daytimer', evt.uuid.string, evt);
            that.emit('update_event_daytimer_' + evt.uuid.string, evt.value);
        });
        that.emit('message_event_table_daytimer', messages);
    });

    this.connection.on('message_event_table_weather', function (messages) {
        messages.forEach(function (evt) {
            that.emit('update_event_weather', evt.uuid.string, evt);
            that.emit('update_event_weather_' + evt.uuid.string, evt.value);
        });
        that.emit('message_event_table_weather', messages);
    });

    this.connection.on('message_invalid', function (message) {
        that.emit('message_invalid', message);
    });

    this.connection.on('keepalive', function (time) {
        that.emit('keepalive', time);
    });
};

API.prototype.reconnect = function () {
    var that = this;
    if (that.connection != undefined) {
        that.connection.removeAllListeners();
        that.connection.close();
    }

    that.connection = undefined;
    that.clear_auth_chain();
    that._status_update_subscription = false;
    that.emit('close', false, 'reconnecting');
    if (that._abort) {
        that.emit('abort');
        return;
    }

    if (that._reconnect) {
        that.emit('reconnect');
        setTimeout(function () {
            if (that.connection === undefined) {
                that.connect();
            }
        }, that._reconnect_timeout);
    }
};

API.prototype.send_control_command = function (control, command) {
    this.connection.send(this._auth.prepare_control_command(control, command));
};

API.prototype.send_command = function (command, secure, command_chain_entry) {
    if (command_chain_entry != undefined) {
        this.register_command_response(command_chain_entry);
    }

    secure = typeof secure !== 'undefined' ? secure : true;
    if (secure) {
        this.connection.send(this._auth.prepare_secure_command(command));
    } else {
        this.connection.send(command);
    }
};

API.prototype.change_password = function (control, username, uuid, password, passwordScore) {
    if (!(this._auth instanceof JWT)) {
        throw new Error("Only available with JWT authentication");
    }

    if (control != "updateuservisupwdh" && control != "updateuserpwdh") {
        throw new Error("Control must be updateuserpwdh or updateuservisupwdh");
    }

    var that = this;
    return new Promise((resolve, reject) => {
        this._auth.send_get_key2(username, password, (key, pw_hash) => {
            that.send_command(`jdev/sps/${control}/${uuid}/${pw_hash}|${passwordScore}`, false, {
                'control': new RegExp(`^j?dev\/sps\/${control}\/${uuid}\/${pw_hash}\|${passwordScore}$`),
                'callback': loxone_message => {
                    if (loxone_message.code != '200') {
                        reject("Failed to update password for user");
                    } else {
                        resolve();
                    }
                },
                'onetime': true,
            });
        });
    });
}

API.prototype.send_cmd = function (uuidAction, command) {
    this.send_control_command(uuidAction, command);
};

API.prototype._message_text = function (message) {
    for (index = this.command_chain.length - 1; index >= 0; index--) {
        var item = this.command_chain[index];
        if (item.control.test(message.control)) {
            item.callback(message);
            if (item.onetime) {
                this.command_chain.splice(index, 1);
            }
            break;
        }
    }
};

API.prototype._message_file = function (message) {
    for (index = this.file_chain.length - 1; index >= 0; index--) {
        var item = this.file_chain[index];
        if (item.file.test(message.filename)) {
            item.callback(message);
            if (item.onetime) {
                this.file_chain.splice(index, 1);
            }
            break;
        }
    }
};

API.prototype.clear_auth_chain = function () {
    this.command_chain = [];
    this.file_chain = [];
    this._auth = undefined;
};

API.prototype.register_auth_object = function () {
    this.emit('info', `Using ${this._security} for auth...`)
    if (this._security === "JWT") {
        this._auth = new (this._auth_class)(this._host, this._username, this._password, this._permissions, this.connection, this);
    } else {
        this._auth = new (this._auth_class)(this._host, this._username, this._password, this.connection, this);
    }

    var that = this;

    this._auth.on('info', function (message) {
        that.emit('info', message);
    })

    this._auth.on('auth_failed', function (loxone_message) {
        that.emit('auth_failed', loxone_message);
    });

    this._auth.on('authorized', function () {
        that._abort = false;
        that.emit('authorized');

        if (that._request_structure_file) {
            that.register_LoxAPPVersion_response();
            that.send_command('jdev/sps/LoxAPPversion3');
        }

        if (that._request_status_updates) {
            that.enable_status_updates();
        }
    });

    this._auth.on('message_text', function (loxone_message) {
        that._message_text(loxone_message);
        that.emit('message_text', loxone_message);
    });
};

API.prototype.register_command_response = function (command_chain_entry) {
    if (!(command_chain_entry.control instanceof RegExp) || typeof command_chain_entry.callback != "function" || typeof command_chain_entry.onetime != "boolean") {
        throw new Error("Invalid chain entry");
    }

    this.command_chain.push(command_chain_entry);
}

API.prototype.register_LoxAPPVersion_response = function () {
    var that = this;
    this.command_chain.push({
        'control': /^j?dev\/sps\/LoxAPPversion3$/,
        'callback': function (loxone_message) {
            that.register_LoxAPP3json_response();
            that.send_command('data/LoxAPP3.json', false);
        },
        'onetime': true,
    });
};

API.prototype.enable_status_updates = function () {
    if (!that._status_update_subscription) {
        that._status_update_subscription = true;
        that.register_enablestatusupdate_response();
        that.send_command('jdev/sps/enablebinstatusupdate');
    }
}

API.prototype.register_LoxAPP3json_response = function () {
    var that = this;
    this.file_chain.push({
        'file': /^data\/LoxAPP3.json/,
        'callback': function (loxone_file) {
            that.emit('get_structure_file', loxone_file.data);
        },
        'onetime': true,
    });
};

API.prototype.register_enablestatusupdate_response = function () {
};

API.prototype.perform_version_check = function (connection) {
    this.emit("info", "Checking version...")

    var that = this;
    https.get('https://' + this._host + '/jdev/cfg/api', (res) => {
        res.on('data', (chunk) => {
            this.emit("info", res.statusCode)

            if (res.statusCode === 200) {
                var json = JSON.parse(chunk);
                that.emit('info', json);

                var api = JSON.parse(json.LL.value.replace(/'/g, '"'));
                var version = api.version.split(".");

                let changed = false;
                if (version[0] >= 10) {
                    that._security = 'JWT';
                    changed = true;
                } else if (version[0] >= 9) {
                    that._security = 'Token-Enc';
                    changed = true;
                }

                if (changed) {
                    that._auth_class = require('./Auth/' + that._security + '.js');
                }


                connection.connect();
            } else {
                that.reconnect();
            }
        });
        res.resume();
    }).on('error', (e) => {
        that.reconnect();
    });
};

module.exports = API;
