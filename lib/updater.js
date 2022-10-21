'use strict';

var join = require('path').join;
var http = require('https');
var fs = require('fs');

var pkg = require('../package.json');

var providerUrl = pkg.tldjs.providers['publicsuffix-org'];
const PUBLIC_SUFFIX_MARKER_ICANN_START = "// ===BEGIN ICANN DOMAINS===";
const PUBLIC_SUFFIX_MARKER_ICANN_END = "// ===END ICANN DOMAINS===";
const PUBLIC_SUFFIX_MARKER_PRIVATE_START = "// ===BEGIN PRIVATE DOMAINS===";
const PUBLIC_SUFFIX_MARKER_PRIVATE_END = "// ===END PRIVATE DOMAINS===";

var parser = require('./parsers/publicsuffix-org.js');

const extractByMarkers = (listContent, startMarker, endMarker) => {
  const start = listContent.indexOf(startMarker);
  const end = listContent.indexOf(endMarker);
  if (start === -1) {
    throw new Error(`Missing start marker ${startMarker} in public suffix list`);
  }
  if (end === -1) {
    throw new Error(`Missing end marker ${endMarker} in public suffix list`);
  }
  return listContent.slice(start, end);
};


module.exports = {
  providerUrl: providerUrl,
  run: function runUpdater(done) {
    done = typeof done === 'function' ? done : function(){};

    var req = http.request(providerUrl, function (res) {
      var body = '';


      if (res.statusCode !== 200) {
        res.destroy();
        return done(new Error('tldjs: remote server responded with HTTP status ' + res.statusCode));
      }

      res.setEncoding('utf8');

      res.on('data', function(d) {

        body += d;
      });

      res.on('end', function() {
        var _icann = extractByMarkers(body, PUBLIC_SUFFIX_MARKER_ICANN_START, PUBLIC_SUFFIX_MARKER_ICANN_END)
        var _private = extractByMarkers(body, PUBLIC_SUFFIX_MARKER_PRIVATE_START, PUBLIC_SUFFIX_MARKER_PRIVATE_END)

        var tlds = parser.parse(body);
        var filename = 'rules.json';
        var data = JSON.stringify(tlds);
        fs.writeFile(join(__dirname, '..', filename), data, 'utf-8', done);

        tlds = parser.parse(_icann);
        filename = 'icann.json';
        data = JSON.stringify(tlds);
        fs.writeFile(join(__dirname, '..', filename), data, 'utf-8', done);

        tlds = parser.parse(_private);
        filename = 'private.json';
        data = JSON.stringify(tlds);
        fs.writeFile(join(__dirname, '..', filename), data, 'utf-8', done);
      });
    });

    req.setTimeout(5000);
    req.on('error', done);
    req.end();
  }
};
