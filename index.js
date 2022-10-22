'use strict';

// Load rules
var Trie = require('./lib/suffix-trie.js');
var allRules = Trie.fromJson(require('./rules.json'));
var icannRules = Trie.fromJson(require('./icann.json'));

// Internals
var extractHostname = require('./lib/clean-host.js');
var getDomain = require('./lib/domain.js');
var getPublicSuffix = require('./lib/public-suffix.js');
var getSubdomain = require('./lib/subdomain.js');
var isValidHostname = require('./lib/is-valid.js');
var isIp = require('./lib/is-ip.js');
var tldExists = require('./lib/tld-exists.js');


// Flags representing steps in the `parse` function. They are used to implement
// a early stop mechanism (simulating some form of laziness) to avoid doing more
// work than necessary to perform a given action (e.g.: we don't need to extract
// the domain and subdomain if we are only interested in public suffix).
var TLD_EXISTS = 1;
var PUBLIC_SUFFIX = 2;
var DOMAIN = 3;
var SITE_DOMAIN = 4;
var SUB_DOMAIN = 5;
var ALL = 6;


/**
 * Creates a new instance of tldjs
 * @param  {Object.<rules,validHosts>} options [description]
 * @return {tldjs|Object}                      [description]
 */
function factory(options) {
  var rules = options.rules || allRules || {};
  var rfc6761Hosts = ['localhost','local','example','invalid','test'];
  var validHosts = (options.rfc6761===true ? [...(rfc6761Hosts),...(options.validHosts || [])] : (options.validHosts || []))
    .filter((v,i,self)=>(i===self.indexOf(v)));
  var _extractHostname = options.extractHostname || extractHostname;

  /**
   * Process a given url and extract all information. This is a higher level API
   * around private functions of `tld.js`. It allows to remove duplication (only
   * extract hostname from url once for all operations) and implement some early
   * termination mechanism to not pay the price of what we don't need (this
   * simulates laziness at a lower cost).
   *
   * @param {string} url
   * @param {number|undefined} _step - where should we stop processing
   * @return {object}
   */
  function parse(url, _step) {
    var step = _step || ALL;
    var result = {
      hostname: _extractHostname(url),
      isValid: null,
      isIp: null,
      isHost: null,
      tldExists: false,
      publicSuffix: null,
      sitedomain: null,
      subdomain: null,
      domain: null,
      icann:{
        tldExists: false,
        publicSuffix: null,
        sitedomain: null,
        subdomain: null,
        domain: null,
      }
    };

    if (result.hostname === null) {
      result.isIp = false;
      result.isHost = false;
      result.isValid = false;
      return result;
    }

    // Check if `hostname` is a valid ip address
    result.isIp = isIp(result.hostname);
    if (result.isIp) {
      result.isHost = false;
      result.isValid = true;
      return result;
    }

    // Check if `hostname` is a valid host
    result.isHost = validHosts.includes(result.hostname)
    if (result.isHost) {
      result.isIp = false
      result.isValid = true;
      return result;
    }


    // Check if `hostname` is valid
    result.isValid = isValidHostname(result.hostname);
    if (result.isValid === false) { return result; }

    // Check if tld exists
    if (step === ALL || step === TLD_EXISTS) {
      result.tldExists = tldExists(rules, result.hostname);
      result.icann.tldExists = tldExists(icannRules, result.hostname);
    }
    if (step === TLD_EXISTS) { return result; }

    // Extract public suffix
    result.publicSuffix = getPublicSuffix(rules, result.hostname);
    result.icann.publicSuffix = getPublicSuffix(icannRules, result.hostname);
    if (step === PUBLIC_SUFFIX) { return result; }

    // Extract domain
    result.domain = getDomain(validHosts, result.publicSuffix, result.hostname);
    result.icann.domain = getDomain(validHosts, result.icann.publicSuffix, result.hostname);
    if (step === DOMAIN) { return result; }

    // Extract sitedomain
    result.sitedomain = result.domain ? result.domain.replace('.'+result.publicSuffix,'') : null;
    result.icann.sitedomain = result.icann.domain ? result.icann.domain.replace('.'+result.icann.publicSuffix,'') : null;
    if (step === SITE_DOMAIN) { return result; }

    // Extract subdomain
    result.subdomain = getSubdomain(result.hostname, result.domain);
    result.icann.subdomain = getSubdomain(result.hostname, result.icann.domain);

    return result;
  }


  return {
    extractHostname: _extractHostname,
    isValidHostname: isValidHostname,
    isValid: function (hostname) {
      // eslint-disable-next-line
      console.error('DeprecationWarning: "isValid" is deprecated, please use "isValidHostname" instead.');
      return isValidHostname(hostname);
    },
    parse: parse,
    tldExists: function (url) {
      return parse(url, TLD_EXISTS).tldExists;
    },
    getPublicSuffix: function (url,icann) {
      const parsed = parse(url, PUBLIC_SUFFIX);
      return icann ? parsed.icann.publicSuffix : parsed.publicSuffix;
    },
    getDomain: function (url,icann) {
      const parsed = parse(url, DOMAIN);
      return icann ? parsed.icann.domain : parsed.domain;
    },
    getSubdomain: function (url,icann) {
      const parsed = parse(url, SUB_DOMAIN);
      return icann ? parsed.icann.subdomain : parsed.subdomain;
    },
    getSitedomain: function (url,icann) {
      const parsed = parse(url, SITE_DOMAIN);
      return icann ? parsed.icann.sitedomain : parsed.sitedomain;
    },
    fromUserSettings: factory,

    rules: function (key) {
      if (key==='icann') return Trie.fromJson(require('./icann.json'));
      if (key==='private') return Trie.fromJson(require('./private.json'));
      return Trie.fromJson(require('./rules.json'));
    }
  };
}


module.exports = factory({});
