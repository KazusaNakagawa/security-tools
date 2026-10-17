// Intentionally leaks stack traces for malformed input (development-style error handling).
const http = require("http");

function handle(req, res) {
  if (req.url.includes("%27") || req.url.includes("[]")) {
    throw new TypeError("Cannot read properties of undefined (reading 'id')");
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
}

http
  .createServer((req, res) => {
    try {
      handle(req, res);
    } catch (err) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(err.stack);
    }
  })
  .listen(3000);
