shadowsocks-heroku
==================

Patch by RainX
------

修改了dotcloud版本的引擎，增加了 ShadowsocksR 里面的obfs_protocol: auth_simple , 但是与ShadowsocksR是不兼容的，因为是HTTP-upgrade-to Websocks 的形式，所以需要配合我开发的一个 Shadowsocks 版本的 shadowsocks-libev 的插件 ws_simple 使用。

* 服务器auth_simple 插件参见 : src/ProtocolAuth.js
* 客户端ws_simple插件参见 ： client_plugins/obfs_ws.c , 需要结合 @breakwa11 的 https://github.com/breakwa11/shadowsocks-libev 编译


shadowsocks-heroku is a lightweight tunnel proxy which can help you get through firewalls. It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks), but through a different protocol.

shadowsocks-heroku uses WebSocket instead of raw sockets, so it can be deployed on [Heroku](https://www.heroku.com/).

Notice that the protocol is INCOMPATIBLE with the origin shadowsocks.

Usage
-----

```
$ heroku create
Creating still-tor-8707... done, stack is cedar
http://still-tor-8707.herokuapp.com/ | git@heroku.com:still-tor-8707.git
```

Push the code to Heroku.

```
$ git push heroku master
Initializing repository, done.
Counting objects: 178, done.
Delta compression using up to 4 threads.
Compressing objects: 100% (97/97), done.
Writing objects: 100% (178/178), 47.42 KiB | 0 bytes/s, done.
Total 178 (delta 89), reused 162 (delta 78)

-----> Node.js app detected
-----> Requested node range:  0.10.x
-----> Resolved node version: 0.10.33
-----> Downloading and installing node
-----> Writing a custom .npmrc to circumvent npm bugs
-----> Exporting config vars to environment
-----> Installing dependencies
       npm WARN package.json shadowsocks-heroku@0.9.7 No repository field.
-----> Cleaning up node-gyp and npm artifacts
-----> Building runtime environment
-----> Discovering process types
       Procfile declares types -> web

-----> Compressing... done, 5.1MB
-----> Launching... done, v3
       http://still-tor-8707.herokuapp.com/ deployed to Heroku

To git@heroku.com:still-tor-8707.git
 * [new branch]      master -> master
```

Set a few configs:

```
$ heroku config:set METHOD=rc4 KEY=foobar
Setting config vars and restarting still-tor-8707... done, v11
KEY:    foobar
METHOD: rc4
```

Then run:

```
$ node local.js -s still-tor-8707.herokuapp.com -l 1080 -m rc4 -k foobar
shadowsocks-heroku v0.9.6
```

Change proxy settings of your browser into:

```
SOCKS5 127.0.0.1:1080
```

Troubleshooting
---------------

If there is something wrong, you can check the logs by:

```
$ heroku logs -t --app still-tor-8707
```
