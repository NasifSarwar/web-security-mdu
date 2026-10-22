var http = require("http");
var fs = require("fs");
var path = require("path");

var mimeTypes = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
};

var url = require('url');

var routes = {
  "GET /information": information,
  "POST /information": information,
};

function route(req, res) {
  var parsedUrl = url.parse(req.url, true);
  var key = req.method + " " + parsedUrl.pathname;
  var handler = routes[key];

  if (handler) {
    handler(req, res, parsedUrl);
  } else {
    serveStatic(req, res);
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function information(req, res, parsedUrl) {
  var templatePath = path.join(__dirname, "templates", "information.template");

  fs.readFile(templatePath, "utf8", (err, template) => {
    var queryRows = Object.keys(parsedUrl.query)
      .map(key => `<li>${escapeHtml(key)} = ${escapeHtml(parsedUrl.query[key])}</li>`)
      .join("");

    var html = template
      .replace("{{method}}", escapeHtml(req.method))
      .replace("{{path}}", escapeHtml(parsedUrl.pathname))
      .replace("{{query}}", escapeHtml(parsedUrl.search || ""))
      .replace("{{queries}}", queryRows);

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  });
}

function serveStatic(req, res) {
  var decodedPath;
  try {
    decodedPath = decodeURIComponent(req.url);
  } catch (err) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("400 Bad Request: malformed URL encoding");
      return;
    }
  var filePath = path.join(__dirname, "public", decodedPath);

  fs.stat(filePath, (err, stats) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end("404 Not Found");
      return;
    }

    if (stats.isFile()) {
      var ext = path.extname(filePath);
      var contentType = mimeTypes[ext] || "application/octet-stream";

      fs.readFile(filePath, (err, data) => {
        res.writeHead(200, { "Content-Type": contentType });
        res.end(data);
      });
    } else if (stats.isDirectory()) {
      if (!req.url.endsWith("/")) {
        res.writeHead(301, { Location: req.url + "/" });
        res.end();
        return;
      }

      var indexPath = path.join(filePath, "index.html");

      fs.stat(indexPath, (err, indexStats) => {
        if (!err && indexStats.isFile()) {
          // index.html exists — serve it
          fs.readFile(indexPath, (err, data) => {
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(data);
          });
        } else {
          // no index.html — build a directory listing
          fs.readdir(filePath, (err, entries) => {
            var links = entries
              .map(
                (name) =>
                  `<li><a href="${encodeURIComponent(name)}">${name}</a></li>`,
              )
              .join("");
            var html = `<html><body><ul>${links}</ul></body></html>`;
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(html);
          });
        }
      });
    }
  });
}

var server = http.createServer((req, res) => {
  var chunks = [];

  req.on("data", (chunk) => {
    chunks.push(chunk);
  });

  req.on("end", () => {
    var body = Buffer.concat(chunks).toString();

    console.log(req.method + " " + req.url + " " + req.httpVersion);
    console.log("Content-Type: " + req.headers["content-type"]);
    console.log("Body: " + body);

    route(req, res);
  });
});

server.listen(8000);
