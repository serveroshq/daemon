// The "app" pm2 runs: answers on 3000 so nginx has something to proxy.
const http = require("http");
http.createServer((_req, res) => res.end("shop ok\n")).listen(3000, "127.0.0.1");
