/**
 * Created by rainx on 16/3/24.
 */

    /*
    参考python 版本的 shadowsocks rss , 去掉 raw_trans 部分..
    auth_simple 的 服务器端实现
     */

const crypto = require('crypto');
const crc32 = require('buffer-crc32');


class ProtocolAuth {

    constructor () {
        this.recv_buf = new Buffer(0);
        this.unit_len = 8100;
        this.decrypt_packet_num = 0;
        this.has_sent_header = false;
        this.has_recv_header = false;
        this.client_id = 0;
        this.connection_id = 0;
        this.max_time_dif = 60 * 60; // 从5分钟修改为1个小时
    }

    initData() {
        return new ObfsAuthData();
    }


    setServerInfo(server_info) {
        this.server_info = server_info;

        // should
        // read from server_info.protocol_param

        if (server_info) {
            this.server_info.data.setMaxClient(16);
        }

    }

    packData(buf) {
        if (buf.length == 0 ){
            return new Buffer(0);
        }

        let randDataLength = parseInt(Math.random() * 16);
        let randData = crypto.randomBytes(randDataLength);

        // create a new buf

        let newLength = 2 + 1 + randDataLength + buf.length + 4;
        let newBuf = new Buffer(newLength);
        newBuf.writeUInt16BE(newLength, 0);
        newBuf[2] = randDataLength + 1;

        randData.copy(newBuf, 3);
        buf.copy(newBuf, 2 + 1 + randDataLength);

        let crcBuf = new Buffer(4);
        let crcBufInt = 0xffffffff ^ crc32.signed(newBuf.slice(0, 2 + 1 + randDataLength + buf.length));
        crcBuf.writeInt32LE(crcBufInt);
        crcBuf.copy(newBuf, 2 + 1 + randDataLength + buf.length);
        return newBuf;
    }

    authData() {
        let utc_time = (parseInt( (new Date().getTime())/1000 ) - 30) & 0xFFFFFFFF;
        if (this.server_info.data.connection_id > 0xFF000000) {
            this.server_info.data.local_client_id = null;
        }

        if (!this.server_info.data.local_client_id || this.server_info.data.local_client_id.length == 0) {
            this.server_info.data.local_client_id =  crypto.randomBytes(4);
            console.log("local_client_id is: " + this.server_info.data.local_client_id.toString("hex"));
            this.server_info.data.connection_id = crypto.randomBytes(4).readUInt32LE(); // get a random number
        }

        this.server_info.data.connection_id += 1;


        let buf = new Buffer(4 + this.server_info.data.local_client_id.length + 4);
        buf.writeUInt32LE(utc_time, 0);
        this.server_info.data.local_client_id.copy(buf, 4);
        buf.writeUInt32LE(this.server_info.data.connection_id, 4 + server_info.data.local_client_id.length);
        return buf;
    }

    serverPreEncrypt(buf) {
        let ret = new Buffer(0);
        while(buf.length > this.unit_len) {
            ret = Buffer.concat([ret, this.packData(buf.slice(0, this.unit_len))]);
            buf = buf.slice(this.unit_len);
        }

        ret = Buffer.concat([ret, this.packData(buf)]);
        return ret;
    }

    serverPostDecrypt(buf) {
        let out_buf = new Buffer(0);
        this.recv_buf = Buffer.concat([this.recv_buf, buf]);

        // console.log("recv_buf is now:", this.recv_buf);

        while (this.recv_buf.length > 2) {
            let length =  this.recv_buf.readUInt16BE(0);

            if (length > this.recv_buf.length) {
                break;
            }

            if (crc32.signed(this.recv_buf.slice(0, length)) != -1) {
                console.log(" crc32 error, data ". this.recv_buf.toString("hex"));
                throw Error("server_post_decrype data uncorrect CRC32");
            }

            let pos = this.recv_buf[2] + 2;

            out_buf = Buffer.concat([out_buf, this.recv_buf.slice(pos, length - 4)]);

            // console.log("out_buf length", out_buf.length, "pos :", pos, "length: ", length);

            if (!this.has_recv_header) {
                let utc_time = out_buf.readUInt32LE(0);
                let client_id = out_buf.readUInt32LE(4);
                let connection_id = out_buf.readUInt32LE(8);

                let time_diff = (parseInt( (new Date().getTime())/1000 ) - 30) & 0xFFFFFFFF - utc_time;
                if (time_diff < -this.max_time_dif || time_diff > this.max_time_dif
                    || (utc_time - this.server_info.data.startup_time) < 0 ) {
                    this.recv_buf = new Buffer(0);
                    console.log({startup_time:this.server_info.data.startup_time, utc_time})
                    console.log("wrong timestamp, time_dif" + time_diff + ", data" + out_buf.toString("hex"));
                    return new Buffer("E");
                } else if (this.server_info.data.insert(client_id, connection_id)) {
                    this.has_recv_header = true;
                    out_buf = out_buf.slice(12);
                    this.client_id = client_id;
                    this.connection_id = connection_id;
                } else {
                    this.recv_buf = new Buffer(0);
                    console.log("auth fail, data " + out_buf.toString("hex"));
                    return new Buffer("E");
                }
            }
            this.recv_buf = this.recv_buf.slice(length);
        }

        if (out_buf) {
            this.server_info.data.update(this.client_id, this.connection_id);
            this.decrypt_packet_num++;
        }

        return out_buf;
    }


    clientPreEncrypt(buf) {

        let ret = new Buffer(0);

        if (!this.has_sent_header) {
            let head_size = getHeadSize(buf, 30);
            let datalen = Math.min(buf.length, parseInt(Math.random() * 32) + head_size);
            ret = this.packData(Buffer.concat( [this.authData(), buf.slice(0, datalen)]));
            buf = buf.slice(datalen);
            this.has_sent_header = true;
        }

        while(buf.length > this.unit_len) {
            ret = Buffer.concat([buf, this.packData(buf.slice(0, this.unit_len))]);
            buf = buf.slice(this.unit_len);
        }

        ret = Buffer.concat([ret, this.packData(buf)]);
        return ret;
    }

    clientPostDecrypt(buf) {

    }

}


class ServerInfo {
    constructor(data) {
        this.data = data;
    }
}


class ObfsAuthData {
    constructor() {
        this.client_id = {}; // [ClientQueue];
        this.startup_time = (parseInt( (new Date().getTime())/1000 ) - 30) & 0xFFFFFFFF ;
        this.local_client_id = new Buffer(0);
        this.connection_id = 0;
        this.setMaxClient(16);
    }

    update(client_id, connection_id) {
        if (client_id in this.client_id) {
            this.client_id[client_id].update();
        }
    }

    setMaxClient(max_client) {
        this.max_client = max_client;
        this.max_buffer = Math.max(max_client * 2 , 256);
    }

    insert(client_id, connection_id) {
        if ( !(client_id in this.client_id) || !this.client_id[client_id].enable) {
            let active = 0;

            for (let cid in this.client_id) {
                if (this.client_id[cid].is_active()) {
                    active++;
                }
            }

            if (active > this.max_client) {
                console.log("max active clients exceeded");
                return false;
            }

            if (Object.keys(this.client_id).length < this.max_client) {
                if (! (client_id in this.client_id ) ) {
                    this.client_id[client_id] = new ClientQueue(connection_id);
                } else {
                    this.client_id[client_id].reEnable(connection_id);
                }

                return this.client_id[client_id].insert(connection_id);
            }

            // else

            let keys = Object.keys(this.client_id);

            keys = shuffle(keys);

            for (let cid in keys) {
                if ( !(this.client_id[cid]).isActive()
                        && this.client_id[cid].enable) {
                    if (this.client_id.length > this.max_buffer) {
                        delete this.client_id[cid];
                    } else {
                        this.client_id[cid].enable = false;
                    }

                    if (!(client_id in this.client_id)) {
                        this.client_id[client_id] = new ClientQueue(connection_id);
                    } else {
                        this.client_id[client_id].insert(connection_id);
                    }

                    return this.client_id[client_id].insert(connection_id);
                }
            }

            console.log("no inactive client");
            return false;
        } else {
            return this.client_id[client_id].insert(connection_id);
        }
    }

}


class ClientQueue {

    constructor(begin_id) {

        this.front = begin_id;
        this.back = begin_id;
        this.alloc = {};
        this.enable = true;
        this.last_update = new Date().getTime()
    }

    update() {
        this.last_update = new Date().getTime();
    }

    isActive() {
        return (new Date().getTime() - this.last_update) < 60 * 3 * 1000;
    }

    reEnable(connection_id) {
        this.enable = true;
        this.alloc = {};
        this.front = connection_id;
        this.back = connection_id;
    }

    insert(connection_id) {
        this.update();

        if (!this.enable) {
            console.log("not enable");
            return false;
        }

        if (connection_id < this.front) {
            console.log("dup id");
            return false;
        }

        if (!this.isActive()) {
            this.reEnable(connection_id);
        }

        if (connection_id > this.front + 0x4000) {
            console.log("wrong id ");
        }

        if (connection_id in this.alloc) {
            console.log("dup id 2");
            return false;
        }

        if (this.back <= connection_id) {
            this.back = connection_id + 1;
        }

        while ( (this.front in this.alloc )
                ||
                (this.front + 0x1000 < this.back)) {

            if (this.front in this.alloc) {
                delete (this.alloc[this.front]);
            }
            this.front++;
        }

        return true;
    }
}



function shuffle(array) {
    var currentIndex = array.length, temporaryValue, randomIndex;

    // While there remain elements to shuffle...
    while (0 !== currentIndex) {

        // Pick a remaining element...
        randomIndex = Math.floor(Math.random() * currentIndex);
        currentIndex -= 1;

        // And swap it with the current element.
        temporaryValue = array[currentIndex];
        array[currentIndex] = array[randomIndex];
        array[randomIndex] = temporaryValue;
    }

    return array;
}


function getHeadSize(buf, def_value) {
    if (buf.length < 2) {
        return def_value;
    }
    var head_type = buf[0] & 0x7;

    if (head_type == 1) {
        return 7;
    } else if (head_type == 4) {
        return 19;
    } else if (head_type == 3) {
        return 4 + buf[1];
    } else {
        return def_value;
    }
}

//export { ProtocolAuth, ServerInfo, ObfsAuthData };

module.exports = { ProtocolAuth, ServerInfo, ObfsAuthData, ClientQueue };