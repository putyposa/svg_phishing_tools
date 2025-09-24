#!/usr/bin/env python3
# dynamic.py — box-js SVG analyzer with aggressive URL/ActiveX/WScript sink hooks
from __future__ import annotations
import argparse, base64, json, re, shutil, subprocess, sys, tempfile
from pathlib import Path
from typing import Iterable, Set, Tuple

BOXJS_CMD = "box-js"
BOXJS_TIMEOUT_DEFAULT = 30
BOXJS_BASE_FLAGS = ["--loglevel=info"]  # prelude injected below

SVG_SCRIPT_RE = re.compile(r'(?is)<script\b[^>]*>(?:\s*<!\[CDATA\[)?(.*?)(?:\]\]>\s*)?</script>')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.IGNORECASE)
GENERIC_URL_RE = re.compile(r'(?i)\b(?:https?:\/\/|\/\/|mailto:)[^\s\'"<>{}|\\^`\[\]]+')
LOCAL_JS_FILENAME_RE = re.compile(r'^[\w\-\./\\]+\.boxed(?:\.js)?$', re.IGNORECASE)
BOXIOC_MARK = "[BOXIOC]"
FINALURL_MARK = "[FINALURL]"

def mask_email(email: str) -> str:
  """Mask email address for privacy: user@example.com -> u***@e*****.com"""
  if '@' not in email:
    return email
  
  user, domain = email.split('@', 1)
  
  # Mask username: keep first char + *** + last char (if >2 chars)
  if len(user) <= 2:
    masked_user = user[0] + '*' * max(1, len(user) - 1)
  else:
    masked_user = user[0] + '*' * max(1, len(user) - 2) + user[-1]
  
  # Mask domain: keep first char + *** + TLD
  domain_parts = domain.split('.')
  if len(domain_parts) >= 2:
    domain_main = domain_parts[0]
    tld = '.'.join(domain_parts[1:])
    
    if len(domain_main) <= 2:
      masked_domain = domain_main[0] + '*' * max(1, len(domain_main) - 1)
    else:
      masked_domain = domain_main[0] + '*' * max(1, len(domain_main) - 2) + domain_main[-1]
    
    masked_domain += '.' + tld
  else:
    # No TLD found, mask the whole domain
    if len(domain) <= 2:
      masked_domain = domain[0] + '*' * max(1, len(domain) - 1)
    else:
      masked_domain = domain[0] + '*' * max(1, len(domain) - 2) + domain[-1]
  
  return masked_user + '@' + masked_domain

# --------- PRELUDE injected into box-js ---------
PRELUDE_JS = r"""
(function(){
  var MARK='[BOXIOC]';
  var FINALURL_MARK='[FINALURL]';
  var g=(typeof globalThis!=='undefined')?globalThis:(typeof window!=='undefined'?window:this);
  var urlParts = {}; // Track URL components
  var finalUrls = new Set(); // Track complete URLs
  
  // Add atob function for base64 decoding (missing in box-js)
  if(typeof g.atob === 'undefined') {
    g.atob = function(str) {
      var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
      var result = '';
      var i = 0;
      str = str.replace(/[^A-Za-z0-9+/]/g, '');
      while (i < str.length) {
        var a = chars.indexOf(str.charAt(i++));
        var b = chars.indexOf(str.charAt(i++));
        var c = chars.indexOf(str.charAt(i++));
        var d = chars.indexOf(str.charAt(i++));
        var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
        result += String.fromCharCode((bitmap >> 16) & 255);
        if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
        if (d !== 64) result += String.fromCharCode(bitmap & 255);
      }
      return result;
    };
  }
  
  function looksURL(s){ try{s=String(s)}catch(e){return false}; return /^(https?:\/\/|\/\/|mailto:)/i.test(s) }
  function looksPartialURL(s){ try{s=String(s)}catch(e){return false}; return /^(https?:\/\/|\/\/|mailto:|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i.test(s) }
  
  function logIOC(x, why){
    try{
      var s=String(x);
      if(looksURL(s)) {
        console.log(MARK+' '+s+(why?('  ;; '+why):''));
        finalUrls.add(s);
        console.log(FINALURL_MARK+' '+s);
      } else if(looksPartialURL(s) && s.length > 5) {
        console.log(MARK+' '+s+(why?('  ;; '+why+' [partial]'):''));
      }
    }catch(e){}
  }
  
  function logIfURL(s, why){ 
    if(looksURL(s)) {
      console.log(MARK+' '+s+(why?('  ;; '+why):''));
      finalUrls.add(s);
      console.log(FINALURL_MARK+' '+s);
    } else if(looksPartialURL(s) && s.length > 5) {
      console.log(MARK+' '+s+(why?('  ;; '+why+' [partial]'):''));
    }
  }
  
  // Track string concatenations that might build URLs
  function trackConcat(result, parts, why) {
    try {
      var fullStr = String(result);
      if(looksURL(fullStr)) {
        console.log(MARK+' '+fullStr+'  ;; '+why+' [concat]');
        finalUrls.add(fullStr);
        console.log(FINALURL_MARK+' '+fullStr);
      }
    } catch(e) {}
  }

  // ---- String concatenation hooks ----
  try {
    var origConcat = String.prototype.concat;
    String.prototype.concat = function() {
      var result = origConcat.apply(this, arguments);
      trackConcat(result, [this].concat(Array.prototype.slice.call(arguments)), 'String.concat');
      return result;
    };
  } catch(e) {}

  // Hook the + operator by wrapping common string operations
  try {
    var origReplace = String.prototype.replace;
    String.prototype.replace = function(search, replacement) {
      var result = origReplace.call(this, search, replacement);
      if(typeof replacement === 'string' && (looksPartialURL(this) || looksPartialURL(replacement))) {
        trackConcat(result, [this, replacement], 'String.replace');
      }
      return result;
    };
  } catch(e) {}

  // ---- Location family (href/assign/replace) ----
  try{
    var loc = { _href:"" };
    Object.defineProperty(g, 'location', {
      configurable:true,
      get:function(){ return { 
        href: loc._href, 
        assign:function(u){
          var finalUrl = String(u)||'';
          logIOC(finalUrl,'location.assign'); 
          loc._href=finalUrl;
          if(looksURL(finalUrl)) {
            finalUrls.add(finalUrl);
            console.log(FINALURL_MARK+' '+finalUrl);
          }
        }, 
        replace:function(u){
          var finalUrl = String(u)||'';
          logIOC(finalUrl,'location.replace'); 
          loc._href=finalUrl;
          if(looksURL(finalUrl)) {
            finalUrls.add(finalUrl);
            console.log(FINALURL_MARK+' '+finalUrl);
          }
        } 
      } },
      set:function(v){ 
        var s=(v&&v.href)?v.href:v; 
        var finalUrl = String(s)||'';
        logIOC(finalUrl,'location='); 
        loc._href=finalUrl;
        if(looksURL(finalUrl)) {
          finalUrls.add(finalUrl);
          console.log(FINALURL_MARK+' '+finalUrl);
        }
      }
    });
    Object.defineProperty(g, 'document', { configurable:true, value: { get location(){return g.location}, set location(v){ g.location=v } }});
  }catch(e){}

  // ---- window.open ----
  try{ var o=g.open; g.open=function(u){logIOC(u,'open'); return o?o.apply(this,arguments):null} }catch(e){}

  // ---- fetch ----
  try{
    if(g.fetch){
      var of=g.fetch.bind(g);
      g.fetch=function(input, init){
        try{ var u=(input && typeof input==='object' && 'url' in input)?input.url:input; logIOC(u,'fetch') }catch(e){}
        try{ return of(input,init) }catch(e){ return Promise.resolve({}) }
      };
    }
  }catch(e){}

  // ---- XHR.open ----
  try{
    if(g.XMLHttpRequest && g.XMLHttpRequest.prototype && g.XMLHttpRequest.prototype.open){
      var xo=g.XMLHttpRequest.prototype.open;
      g.XMLHttpRequest.prototype.open=function(m,u){ logIOC(u,'XMLHttpRequest.open'); return xo.apply(this,arguments) };
    }
  }catch(e){}

  // ---- Image.src ----
  try{
    if(g.Image && g.Image.prototype){
      var d=Object.getOwnPropertyDescriptor(g.Image.prototype,'src');
      if(d && d.set){
        Object.defineProperty(g.Image.prototype,'src',{
          configurable:true,
          get:d.get,
          set:function(v){ logIOC(v,'Image.src'); try{return d.set.call(this,v)}catch(e){} }
        });
      }
    }
  }catch(e){}

  // ---- navigator.sendBeacon ----
  try{
    if(g.navigator && typeof g.navigator.sendBeacon==='function'){
      var sb=g.navigator.sendBeacon.bind(g.navigator);
      g.navigator.sendBeacon=function(u,d){ logIOC(u,'sendBeacon'); try{ return sb(u,d) }catch(e){ return false } };
    }
  }catch(e){}

  // ---- Common decoders -> log decoded strings that look like URLs ----
  function wrap1(name){
    try{
      var fn=g[name]; if(typeof fn!=='function') return;
      g[name]=function(a){
        var r; try{ r=fn(a) }catch(e){ r='' }
        logIfURL(r, name+'('+a+')');
        return r;
      };
    }catch(e){}
  }
  ['atob','decodeURI','decodeURIComponent','unescape'].forEach(wrap1);

  // ---- eval / Function / timers: scan code for URLs after decode ----
  var URLRX=/(https?:\/\/|\/\/)[^\s'"]+/ig;
  function scanAndLog(s, why){
    try{
      var m, seen={};
      while((m=URLRX.exec(String(s)))!==null){
        var u=m[0]; if(!seen[u]){seen[u]=1; console.log(MARK+' '+u+'  ;; '+why); }
      }
    }catch(e){}
  }
  try{
    var oe=g.eval; g.eval=function(s){ scanAndLog(s,'eval'); return oe?oe(s):undefined };
  }catch(e){}
  try{
    var OF=g.Function; g.Function=function(){ try{ var body=arguments[arguments.length-1]; scanAndLog(body,'Function') }catch(e){}; return OF.apply(this,arguments) };
  }catch(e){}
  try{
    var ost=g.setTimeout; if(ost){ g.setTimeout=function(fn,ms){ try{ if(typeof fn==='string') scanAndLog(fn,'setTimeout') }catch(e){}; return ost.apply(this,arguments) } }
  }catch(e){}
  try{
    var osi=g.setInterval; if(osi){ g.setInterval=function(fn,ms){ try{ if(typeof fn==='string') scanAndLog(fn,'setInterval') }catch(e){}; return osi.apply(this,arguments) } }
  }catch(e){}

  // ---- WScript & ActiveX hooks (box-js emulates these) ----
  function wrapRunLike(obj, name, why){
    try{
      if(obj && typeof obj[name]==='function'){
        var o=obj[name].bind(obj);
        obj[name]=function(){ try{
          var arg=arguments[0]; if(arg){ // often a command or URL
            scanAndLog(arg, why); if(looksURL(arg)) console.log(MARK+' '+arg+'  ;; '+why);
          }
        }catch(e){}; try{return o.apply(this,arguments)}catch(e){return undefined} };
      }
    }catch(e){}
  }

  try{
    // WScript.Shell.Run / Exec
    if(g.WScript && g.WScript.CreateObject){
      var oco=g.WScript.CreateObject.bind(g.WScript);
      g.WScript.CreateObject=function(progId){
        var obj; try{ obj=oco(progId) }catch(e){ obj={} }
        try{
          if(/WScript\.Shell/i.test(progId) && obj){
            wrapRunLike(obj, 'Run', 'WScript.Shell.Run');
            wrapRunLike(obj, 'Exec', 'WScript.Shell.Exec');
          }
        }catch(e){}
        return obj;
      };
    }
  }catch(e){}

  // ActiveXObject(XMLHTTP / WinHttpRequest / ADODB.Stream)
  try{
    var mkXHR=function(orig){
      return {
        open:function(m,u){ logIOC(u,'ActiveX.XMLHTTP.open'); try{ return orig.open?orig.open.apply(this,arguments):undefined }catch(e){ return undefined } },
        send:function(){ try{ return orig.send?orig.send.apply(this,arguments):undefined }catch(e){ return undefined } }
      };
    };
    var mkWinHttp=function(orig){
      return {
        Open:function(m,u,async){ logIOC(u,'WinHttpRequest.Open'); try{ return orig.Open?orig.Open.apply(this,arguments):undefined }catch(e){ return undefined } },
        Send:function(){ try{ return orig.Send?orig.Send.apply(this,arguments):undefined }catch(e){ return undefined } }
      };
    };

    function wrapAX(factory){
      return function(progId){
        var id=String(progId||'');
        var obj;
        try{ obj=factory(progId) }catch(e){ obj={} }
        try{
          if(/MSXML2\.XMLHTTP|Microsoft\.XMLHTTP/i.test(id) && obj) return mkXHR(obj);
          if(/WinHttp\.WinHttpRequest/i.test(id) && obj) return mkWinHttp(obj);
          if(/ADODB\.Stream/i.test(id) && obj){
            // log SaveToFile path via simple proxy
            var proxy=Object.create(obj);
            try{
              proxy.SaveToFile=function(path,mode){ console.log(MARK+' file://'+path+'  ;; ADODB.Stream.SaveToFile'); try{ return obj.SaveToFile.apply(obj,arguments) }catch(e){ return undefined } };
            }catch(e){}
            return proxy;
          }
        }catch(e){}
        return obj;
      }
    }

    if(typeof g.ActiveXObject==='function'){
      var oAX=g.ActiveXObject.bind(g);
      g.ActiveXObject=wrapAX(oAX);
    }
    // Some samples use `new ActiveXObject(...)` path; above handles it since it's the same callable.
  }catch(e){}

  // ---- Final URL summary ----
  try {
    setTimeout(function() {
      console.log('=== FINAL URL SUMMARY ===');
      if(finalUrls.size > 0) {
        finalUrls.forEach(function(url) {
          console.log(FINALURL_MARK + ' ' + url + '  ;; FINAL_COMPLETE_URL');
        });
      } else {
        console.log('No complete URLs detected');
      }
      console.log('=== END FINAL URL SUMMARY ===');
    }, 100);
  } catch(e) {}
})();
"""

def find_svgs(p: Path):
  if p.is_file(): return [p]
  return sorted(p.rglob("*.svg"))

def extract_scripts(svg_text: str):
  scripts = []
  
  # Extract inline scripts
  for m in SVG_SCRIPT_RE.finditer(svg_text):
    script_content = m.group(1) or ""
    # Clean up script content for better parsing
    script_content = clean_script_content(script_content)
    if script_content.strip():
      scripts.append(script_content)
  
  # Extract data URI scripts
  data_uri_pattern = re.compile(r'<script[^>]+src=["\']data:[^;]+;base64,([^"\']+)["\']', re.I)
  for m in data_uri_pattern.finditer(svg_text):
    b64_content = m.group(1)
    try:
      # Fix base64 padding if needed
      missing_padding = len(b64_content) % 4
      if missing_padding:
        b64_content += '=' * (4 - missing_padding)
      
      decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
      decoded = clean_script_content(decoded)
      if decoded.strip():
        scripts.append(decoded)
    except Exception:
      pass  # Skip if can't decode
  
  return scripts

def clean_script_content(script: str) -> str:
  """Clean script content to remove CDATA, comments, and fix syntax issues"""
  # Remove CDATA markers
  script = re.sub(r'<!\[CDATA\[', '', script)
  script = re.sub(r'\]\]>', '', script)
  
  # Remove multi-line comments that start with ///
  lines = script.split('\n')
  cleaned_lines = []
  for line in lines:
    stripped = line.strip()
    # Skip lines that are just comments or XML-like content
    if (stripped.startswith('///') or 
        stripped.startswith('<!--') or 
        stripped.endswith('-->') or
        stripped.startswith('<![CDATA[') or
        stripped.endswith(']]>')):
      continue
    cleaned_lines.append(line)
  
  return '\n'.join(cleaned_lines)

def convert_to_es5(js_code: str) -> str:
  """Convert modern JavaScript to ES5 compatible for box-js and add URL logging"""
  
  # First, convert const and let to var for box-js compatibility
  result = re.sub(r'\b(const|let)\b', 'var', js_code)
  
  # Add atob implementation if atob is used
  if 'atob(' in result and 'function atob(' not in result:
    atob_impl = '''
    if(typeof atob === 'undefined') {
      var atob = function(str) {
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
        var result = '';
        var i = 0;
        str = str.replace(/[^A-Za-z0-9+/]/g, '');
        while (i < str.length) {
          var a = chars.indexOf(str.charAt(i++));
          var b = chars.indexOf(str.charAt(i++));
          var c = chars.indexOf(str.charAt(i++));
          var d = chars.indexOf(str.charAt(i++));
          var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
          result += String.fromCharCode((bitmap >> 16) & 255);
          if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
          if (d !== 64) result += String.fromCharCode(bitmap & 255);
        }
        return result;
      };
    }
    '''
    result = atob_impl + '\n' + result
  
  # Add fetch implementation if fetch is used
  if 'fetch(' in result and 'function fetch(' not in result:
    fetch_impl = '''
    if(typeof fetch === 'undefined') {
      var fetch = function(url, options) {
        console.log("[FINALURL] Dynamic execution code: fetch(" + JSON.stringify(url) + ")");
        // Return a mock promise that resolves to empty response
        return {
          then: function(callback) {
            if (callback) {
              try {
                var mockResponse = {
                  text: function() {
                    return {
                      then: function(textCallback) {
                        if (textCallback) textCallback("");
                        return { then: function() {}, catch: function() {} };
                      },
                      catch: function() { return { then: function() {} }; }
                    };
                  }
                };
                callback(mockResponse);
              } catch(e) {}
            }
            return { then: function() {}, catch: function() {} };
          },
          catch: function() { return { then: function() {} }; }
        };
      };
    }
    '''
    result = fetch_impl + '\n' + result
  
  # Handle simple hex decoding pattern (Pattern 2 simplified)
  if 'parseInt(' in result and '.substr(' in result and 'String.fromCharCode(' in result and '[].constructor.constructor' in result:
    print(f"  [DEBUG] Detected simple hex decoding pattern, analyzing...")
    
    # This pattern uses simple hex decoding: parseInt(hex.substr(i, 2), 16)
    # Override Function constructor BEFORE the original execution happens
    function_override = '''
// Override Function constructor to log what gets executed
var origFunction = [].constructor.constructor;
[].constructor.constructor = function(code) {
  console.log("[FINALURL] Generic eval code: " + code);
  // Try to execute and catch any URLs
  try {
    return origFunction(code);
  } catch (e) {
    console.log("[ERROR] Simple hex execution failed: " + e);
    return function() {};
  }
};

'''
    
    # Insert the override at the beginning of the script
    result = function_override + result
  
  # Handle hex-encoded dynamic execution pattern
  elif ('[].constructor.constructor' in result or 'ckD(YuZ)()' in result) and 'oJx' in result:
    print(f"  [DEBUG] Detected hex-encoded dynamic execution pattern, analyzing...")
    
    # This pattern uses dynamic hex decoding and then executes the result
    # Override Function constructor BEFORE the original execution happens
    function_override = '''
// Override Function constructor to log what gets executed
var origFunction = [].constructor.constructor;
[].constructor.constructor = function(code) {
  console.log("[FINALURL] Dynamic execution code: " + code);
  // Try to execute and catch any URLs
  try {
    return origFunction(code);
  } catch (e) {
    console.log("[ERROR] Dynamic execution failed: " + e);
    return function() {};
  }
};

'''
    
    # Insert the override at the beginning of the script
    result = function_override + result
  
  # Handle XOR + dynamic eval construction pattern
  elif ('Object.keys(L).sort()' in result or 'decodeURIComponent(e)' in result) and 'charCodeAt(C++' in result:
    print(f"  [DEBUG] Detected XOR + dynamic eval construction pattern, analyzing...")
    
    # This pattern uses XOR decoding and dynamic eval construction
    # Add atob function and eval override BEFORE the original execution happens
    eval_override = '''
// Add missing atob function for box-js compatibility
if(typeof atob === 'undefined') {
  var atob = function(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var result = '';
    var i = 0;
    str = str.replace(/[^A-Za-z0-9+/]/g, '');
    while (i < str.length) {
      var a = chars.indexOf(str.charAt(i++));
      var b = chars.indexOf(str.charAt(i++));
      var c = chars.indexOf(str.charAt(i++));
      var d = chars.indexOf(str.charAt(i++));
      var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
      result += String.fromCharCode((bitmap >> 16) & 255);
      if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
      if (d !== 64) result += String.fromCharCode(bitmap & 255);
    }
    return result;
  };
}

// Override eval to log what gets executed
var origEval = eval;
eval = function(code) {
  console.log("[FINALURL] Dynamic eval code: " + code);
  try {
    return origEval(code);
  } catch (e) {
    console.log("[ERROR] Eval execution failed: " + e);
    return undefined;
  }
};

'''
    
    # Insert the override at the beginning of the script
    result = eval_override + result
  
  # Handle character mapping + find() execution pattern
  elif ('String.fromCharCode(j[' in result or '.find(() =>' in result) and 'filter.constructor' in result:
    print(f"  [DEBUG] Detected character mapping + find() execution pattern, analyzing...")
    
    # This pattern uses character mapping and Array.find() execution
    # Add atob function and eval override BEFORE the original execution happens
    eval_override = '''
// Add missing atob function for box-js compatibility
if(typeof atob === 'undefined') {
  var atob = function(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var result = '';
    var i = 0;
    str = str.replace(/[^A-Za-z0-9+/]/g, '');
    while (i < str.length) {
      var a = chars.indexOf(str.charAt(i++));
      var b = chars.indexOf(str.charAt(i++));
      var c = chars.indexOf(str.charAt(i++));
      var d = chars.indexOf(str.charAt(i++));
      var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
      result += String.fromCharCode((bitmap >> 16) & 255);
      if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
      if (d !== 64) result += String.fromCharCode(bitmap & 255);
    }
    return result;
  };
}

// Override eval to log what gets executed
var origEval = eval;
eval = function(code) {
  console.log("[FINALURL] Character mapping eval code: " + code);
  try {
    return origEval(code);
  } catch (e) {
    console.log("[ERROR] Character mapping eval execution failed: " + e);
    return undefined;
  }
};

'''
    
    # Insert the override at the beginning of the script
    result = eval_override + result
  
  # Handle arithmetic character code eval construction pattern
  elif ('String.fromCharCode(' in result and 'Y.S +' in result) or ('Function("return this")' in result and 'parseInt(' in result):
    print(f"  [DEBUG] Detected arithmetic character code eval construction pattern, analyzing...")
    
    # This pattern uses arithmetic to build character codes for "eval"
    # Add atob function and eval override BEFORE the original execution happens
    eval_override = '''
// Add missing atob function for box-js compatibility
if(typeof atob === 'undefined') {
  var atob = function(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var result = '';
    var i = 0;
    str = str.replace(/[^A-Za-z0-9+/]/g, '');
    while (i < str.length) {
      var a = chars.indexOf(str.charAt(i++));
      var b = chars.indexOf(str.charAt(i++));
      var c = chars.indexOf(str.charAt(i++));
      var d = chars.indexOf(str.charAt(i++));
      var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
      result += String.fromCharCode((bitmap >> 16) & 255);
      if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
      if (d !== 64) result += String.fromCharCode(bitmap & 255);
    }
    return result;
  };
}

// Override eval to log what gets executed
var origEval = eval;
eval = function(code) {
  console.log("[FINALURL] Arithmetic eval code: " + code);
  try {
    return origEval(code);
  } catch (e) {
    console.log("[ERROR] Arithmetic eval execution failed: " + e);
    return undefined;
  }
};

'''
    
    # Insert the override at the beginning of the script
    result = eval_override + result
  
  # Handle common obfuscation patterns (catch-all for variants)
  elif any(pattern in result for pattern in [
    'setTimeout(', 'setInterval(', 'Promise.resolve()', '.then(',
    'new Function(', 'Function.constructor', 'eval.call(',
    '(1,eval)', '(0,eval)', 'String.fromCharCode(',
    'addEventListener(', 'dispatchEvent(', 'parseInt(',
    'atob(', 'btoa(', 'decodeURI', 'unescape(',
    'constructor("return', 'filter.constructor'
  ]) and any(suspicious in result for suspicious in [
    'window.location', 'document.location', '.href =',
    'charAt(', 'charCodeAt(', 'fromCharCode(',
    'split(', 'join(', 'slice(', 'substr('
  ]):
    print(f"  [DEBUG] Detected common obfuscation pattern, adding safety overrides...")
    
    # Add comprehensive overrides for any suspicious dynamic execution
    safety_override = '''
// Add missing atob function for box-js compatibility
if(typeof atob === 'undefined') {
  var atob = function(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var result = '';
    var i = 0;
    str = str.replace(/[^A-Za-z0-9+/]/g, '');
    while (i < str.length) {
      var a = chars.indexOf(str.charAt(i++));
      var b = chars.indexOf(str.charAt(i++));
      var c = chars.indexOf(str.charAt(i++));
      var d = chars.indexOf(str.charAt(i++));
      var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
      result += String.fromCharCode((bitmap >> 16) & 255);
      if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
      if (d !== 64) result += String.fromCharCode(bitmap & 255);
    }
    return result;
  };
}

// Override eval and Function constructor
var origEval = eval;
eval = function(code) {
  console.log("[FINALURL] Generic eval code: " + code);
  try {
    return origEval(code);
  } catch (e) {
    console.log("[ERROR] Generic eval execution failed: " + e);
    return undefined;
  }
};

var origFunction = Function;
Function = function() {
  var code = arguments[arguments.length - 1];
  console.log("[FINALURL] Generic Function code: " + code);
  try {
    return origFunction.apply(this, arguments);
  } catch (e) {
    console.log("[ERROR] Generic Function execution failed: " + e);
    return function() {};
  }
};

// Override setTimeout for delayed execution
if(typeof setTimeout !== 'undefined') {
  var origSetTimeout = setTimeout;
  setTimeout = function(func, delay) {
    if(typeof func === 'string') {
      console.log("[FINALURL] setTimeout eval code: " + func);
      try {
        return origSetTimeout(function() { origEval(func); }, delay);
      } catch (e) {
        console.log("[ERROR] setTimeout execution failed: " + e);
        return 0;
      }
    }
    return origSetTimeout.apply(this, arguments);
  };
}

'''
    
    # Insert the override at the beginning of the script
    result = safety_override + result
  
  # Handle XOR + Proxy eval pattern - add forced execution at the end
  elif 'new Proxy(' in result and 'Symbol.toPrimitive' in result:
    print(f"  [DEBUG] Detected XOR + Proxy pattern, analyzing...")
    
    # Look for the pattern where eval is hidden in a proxy
    # Find the variable that contains the decoded URL (usually 'h')
    # Find the variable that contains "eval" (usually constructed from array)
    # Add direct execution at the end
    
    url_var_match = re.search(r'(\w+)\s*\+=\s*"%"\s*\+[^;]+\.toString\(16\)', result)
    eval_var_match = re.search(r'var\s+(\w+)\s*=\s*\[.*?\]\.join\(', result)
    global_var_match = re.search(r'var\s+(\w+)\s*=\s*\[\]\.filter\.constructor\("return this"\)', result)
    
    print(f"  [DEBUG] URL var match: {url_var_match.group(1) if url_var_match else None}")
    print(f"  [DEBUG] Eval var match: {eval_var_match.group(1) if eval_var_match else None}")
    print(f"  [DEBUG] Global var match: {global_var_match.group(1) if global_var_match else None}")
    
    if url_var_match and eval_var_match and global_var_match:
      print(f"  [DEBUG] All patterns matched, adding XOR execution code...")
      url_var = url_var_match.group(1)
      eval_var = eval_var_match.group(1) 
      global_var = global_var_match.group(1)
      
      # Replace the proxy execution (N + "") with our direct execution
      proxy_execution_pattern = r'(\w+)\s*\+\s*""\s*;'
      def replace_proxy_execution(match):
        return f'// Proxy execution replaced with direct XOR decode'
      
      result = re.sub(proxy_execution_pattern, replace_proxy_execution, result)
      
      # Add direct execution at the end with atob function
      result += f'''
      
      // Ensure atob is available for eval
      if(typeof atob === 'undefined') {{
        var atob = function(str) {{
          var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
          var result = '';
          var i = 0;
          str = str.replace(/[^A-Za-z0-9+/]/g, '');
          while (i < str.length) {{
            var a = chars.indexOf(str.charAt(i++));
            var b = chars.indexOf(str.charAt(i++));
            var c = chars.indexOf(str.charAt(i++));
            var d = chars.indexOf(str.charAt(i++));
            var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
            result += String.fromCharCode((bitmap >> 16) & 255);
            if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
            if (d !== 64) result += String.fromCharCode(bitmap & 255);
          }}
          return result;
        }};
      }}
      
      try {{
        console.log("[FINALURL] XOR decoded URL variable: " + {url_var});
        console.log("[FINALURL] Eval variable: " + {eval_var});
        var __decoded_url = decodeURIComponent({url_var});
        console.log("[FINALURL] Decoded URL code: " + __decoded_url);
        
        // Try to execute the decoded JavaScript to get the final URL
        try {{
          {global_var}[{eval_var}](__decoded_url);
        }} catch (eval_error) {{
          console.log("[ERROR] Eval failed, trying manual parsing: " + eval_error);
          
          // Manual parsing - look for window.location.href = atob(...) + variable patterns
          if(__decoded_url.indexOf('window.location.href') !== -1) {{
            console.log("[FINALURL] Found window.location.href assignment, attempting manual decode");
            
            // Extract the email variable (usually 'i')
            var email_var = '';
            if(__decoded_url.indexOf('+i') !== -1) email_var = i;
            
            // Look for concatenated base64 strings in the decoded URL
            // Pattern: atob("part1"+"part2"+...)+variable
            var b64_parts = [];
            var concat_pattern = /atob\s*\(\s*([^)]+)\s*\)/;
            var atob_match = concat_pattern.exec(__decoded_url);
            if (atob_match) {{
              var atob_content = atob_match[1];
              console.log("[FINALURL] Found atob content: " + atob_content);
              
              // Extract individual base64 strings
              var b64_pattern = /["']([^"']+)["']/g;
              var b64_match;
              var combined_b64 = '';
              while ((b64_match = b64_pattern.exec(atob_content)) !== null) {{
                combined_b64 += b64_match[1];
              }}
              
              if (combined_b64) {{
                try {{
                  var decoded_url = atob(combined_b64);
                  console.log("[FINALURL] Decoded base URL: " + decoded_url);
                  if (email_var) {{
                    var final_url = decoded_url + email_var;
                    console.log("[FINALURL] " + final_url + "  ;; manual_xor_decode");
                  }}
                }} catch (decode_error) {{
                  console.log("[ERROR] Failed to decode combined base64: " + decode_error);
                }}
              }}
            }}
          }}
        }}
      }} catch (e) {{
        console.log("[ERROR] XOR execution failed: " + e);
      }}
      '''
  
  # Remove async/await syntax and convert to regular function
  # Pattern: try {(async function() { ... })(); } catch (e) {}
  async_pattern = r'try\s*\{\s*\(\s*async\s+function\s*\(\s*\)\s*\{\s*(.*?)\s*\}\s*\)\s*\(\s*\)\s*;\s*\}\s*catch\s*\(\s*\w+\s*\)\s*\{\s*\}'
  
  def replace_async(match):
    inner_code = match.group(1)
    # Convert to regular try-catch with immediate function
    return f'try {{ (function() {{ {inner_code} }})(); }} catch (e) {{}}'
  
  result = re.sub(async_pattern, replace_async, result, flags=re.DOTALL)
  
  # Add URL interception directly into the code (only if XOR pattern wasn't applied)
  # Look for window.location.href assignments and add logging
  if not ('new Proxy(' in result and 'Symbol.toPrimitive' in result):
    location_pattern = r'window\.location\.href\s*=\s*([^;]+);?'
    
    def replace_location(match):
      url_expr = match.group(1)
      # Add explicit console logging before the assignment
      return f'''
      try {{
        var __final_url = {url_expr};
        console.log("[FINALURL] " + __final_url + "  ;; dynamic_url_construction");
        window.location.href = __final_url;
      }} catch (e) {{
        console.log("[ERROR] Failed to construct URL: " + e);
      }}'''
    
    result = re.sub(location_pattern, replace_location, result)
  
  # Final catch-all for any remaining JavaScript that might contain URLs
  if not any([
    '[FINALURL]' in result,  # Already has our overrides
    'console.log(' in result and '[FINALURL]' in result,  # Already processed
    result.strip().startswith('//')  # Just comments
  ]) and any([
    'location' in result, 'href' in result, 'atob(' in result,
    'eval(' in result, 'Function(' in result, 'constructor(' in result
  ]):
    print(f"  [DEBUG] Adding minimal safety overrides for unrecognized pattern...")
    
    minimal_override = '''
// Minimal safety overrides for unrecognized patterns
if(typeof atob === 'undefined') {
  var atob = function(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var result = '';
    var i = 0;
    str = str.replace(/[^A-Za-z0-9+/]/g, '');
    while (i < str.length) {
      var a = chars.indexOf(str.charAt(i++));
      var b = chars.indexOf(str.charAt(i++));
      var c = chars.indexOf(str.charAt(i++));
      var d = chars.indexOf(str.charAt(i++));
      var bitmap = (a << 18) | (b << 12) | (c << 6) | d;
      result += String.fromCharCode((bitmap >> 16) & 255);
      if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
      if (d !== 64) result += String.fromCharCode(bitmap & 255);
    }
    return result;
  };
}

'''
    result = minimal_override + result
  
  return result

def write_temp_js(scripts, out_dir: Path, base_name: str) -> Path:
  out_dir.mkdir(parents=True, exist_ok=True)
  js_path = out_dir / f"{base_name}.boxed.js"
  with js_path.open("wb") as f:
    for i, s in enumerate(scripts):
      if s.strip():  # Only write non-empty scripts
        f.write(f"// ---- script boundary {i} ----\n".encode("utf-8"))
        # Ensure each script ends with semicolon to prevent syntax issues
        script_content = s.strip()
        
        # Convert modern JS syntax to ES5 for box-js compatibility
        script_content = convert_to_es5(script_content)
        
        if script_content and not script_content.endswith((';', '}')):
          script_content += ';'
        f.write(script_content.encode("utf-8", errors="replace"))
        f.write(b"\n\n")
  return js_path

def write_prelude(out_dir: Path) -> Path:
  prelude = out_dir / "prelude.ioc.js"
  prelude.write_text(PRELUDE_JS, encoding="utf-8")
  return prelude

def run_boxjs(js_path: Path, result_dir: Path, prelude_path: Path, timeout: int) -> Tuple[bool, str]:
  result_dir.mkdir(parents=True, exist_ok=True)
  flags = BOXJS_BASE_FLAGS + [f"--prepended-code={prelude_path}"]
  cmd = [BOXJS_CMD] + flags + ["--output-dir", str(result_dir), str(js_path)]
  try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    (result_dir / "analysis.stdout.log").write_text(p.stdout + "\n\nSTDERR:\n" + p.stderr, encoding="utf-8")
    return (p.returncode == 0), p.stdout + "\n\nSTDERR:\n" + p.stderr
  except subprocess.TimeoutExpired:
    (result_dir / "analysis.stdout.log").write_text("TIMEOUT (expired)\n", encoding="utf-8")
    return False, "TIMEOUT"
  except FileNotFoundError:
    print("[!] 'box-js' not found. Install with: npm install -g box-js", file=sys.stderr)
    sys.exit(3)

def gather_results(result_dir: Path, raw_emails: set = None) -> Tuple[Set[str], Set[str]]:
  urls, emails = set(), set()
  final_urls = set()  # Track the final complete URLs
  
  # Include emails from the raw SVG file
  if raw_emails:
    emails.update(raw_emails)
  
  top = result_dir / "analysis.stdout.log"
  if top.exists():
    txt = top.read_text(encoding="utf-8", errors="ignore")
    
    # Extract emails first (before parsing JS)
    for em in EMAIL_RE.findall(txt): 
      emails.add(em)
    
    # DEBUG: Show all box-js output
    print(f"  [DEBUG] Box-js stdout content:")
    for i, line in enumerate(txt.splitlines()[:20], 1):  # Show first 20 lines
      print(f"    {i:2}: {line}")
    if len(txt.splitlines()) > 20:
      print(f"    ... and {len(txt.splitlines()) - 20} more lines")
    
    print(f"  [DEBUG] Emails found in box-js output: {emails}")
    
    # First priority: Extract FINALURL markers (complete URLs)
    finalurl_count = 0
    for line in txt.splitlines():
      if FINALURL_MARK in line:
        finalurl_count += 1
        print(f"  [DEBUG] Found FINALURL marker: {line}")
        try:
          part = line.split(FINALURL_MARK, 1)[1].strip()
          if part:
            final_url = part.split("  ;;", 1)[0].strip()
            if final_url and is_http_like(final_url):
              final_urls.add(final_url)
              print(f"  [DEBUG] Added final URL: {final_url}")
            elif "Decoded URL code:" in part:
              # Parse the decoded JavaScript to extract the final URL
              js_code = part.replace("Decoded URL code:", "").strip()
              print(f"  [DEBUG] Parsing JavaScript: {js_code}")
              parsed_url = parse_js_url_construction(js_code, emails)
              if parsed_url:
                final_urls.add(parsed_url)
                print(f"  [DEBUG] Parsed final URL: {parsed_url}")
            elif "Dynamic execution code:" in part:
              # Parse dynamic execution code for URLs
              js_code = part.replace("Dynamic execution code:", "").strip()
              print(f"  [DEBUG] Parsing dynamic execution: {js_code}")
              parsed_url = parse_dynamic_execution_url(js_code, emails)
              if parsed_url:
                final_urls.add(parsed_url)
                print(f"  [DEBUG] Extracted dynamic URL: {parsed_url}")
            elif "Dynamic eval code:" in part:
              # Parse dynamic eval code for URLs (similar to XOR + Proxy pattern)
              js_code = part.replace("Dynamic eval code:", "").strip()
              print(f"  [DEBUG] Parsing dynamic eval: {js_code}")
              parsed_url = parse_js_url_construction(js_code, emails)
              if parsed_url:
                final_urls.add(parsed_url)
                print(f"  [DEBUG] Extracted eval URL: {parsed_url}")
            elif "Character mapping eval code:" in part:
              # Parse character mapping eval code for URLs
              js_code = part.replace("Character mapping eval code:", "").strip()
              print(f"  [DEBUG] Parsing character mapping eval: {js_code}")
              parsed_url = parse_js_url_construction(js_code, emails)
              if parsed_url:
                final_urls.add(parsed_url)
                print(f"  [DEBUG] Extracted character mapping URL: {parsed_url}")
            elif "Arithmetic eval code:" in part:
              # Parse arithmetic eval code for URLs
              js_code = part.replace("Arithmetic eval code:", "").strip()
              print(f"  [DEBUG] Parsing arithmetic eval: {js_code}")
              parsed_url = parse_js_url_construction(js_code, emails)
              if parsed_url:
                final_urls.add(parsed_url)
                print(f"  [DEBUG] Extracted arithmetic URL: {parsed_url}")
            elif "Generic eval code:" in part or "Generic Function code:" in part:
              # Parse generic eval/Function code for URLs
              js_code = part.replace("Generic eval code:", "").replace("Generic Function code:", "").strip()
              print(f"  [DEBUG] Parsing generic execution: {js_code}")
              # Try both parsing methods
              parsed_url = parse_js_url_construction(js_code, emails)
              if not parsed_url:
                parsed_url = parse_dynamic_execution_url(js_code, emails)
              if parsed_url:
                final_urls.add(parsed_url)
                print(f"  [DEBUG] Extracted generic URL: {parsed_url}")
            elif "setTimeout eval code:" in part:
              # Parse setTimeout eval code for URLs
              js_code = part.replace("setTimeout eval code:", "").strip()
              print(f"  [DEBUG] Parsing setTimeout eval: {js_code}")
              parsed_url = parse_js_url_construction(js_code, emails)
              if not parsed_url:
                parsed_url = parse_dynamic_execution_url(js_code, emails)
              if parsed_url:
                final_urls.add(parsed_url)
                print(f"  [DEBUG] Extracted setTimeout URL: {parsed_url}")
        except Exception as e:
          print(f"  [DEBUG] Failed to parse FINALURL: {e}")
    
    print(f"  [DEBUG] Total FINALURL markers found: {finalurl_count}")
    
    # Secondary: Extract regular BOXIOC markers
    boxioc_count = 0
    for line in txt.splitlines():
      if BOXIOC_MARK in line and FINALURL_MARK not in line:
        boxioc_count += 1
        print(f"  [DEBUG] Found BOXIOC marker: {line}")
        try:
          part = line.split(BOXIOC_MARK, 1)[1].strip()
          if part:
            url = part.split("  ;;", 1)[0].strip()
            if url:
              urls.add(url)
        except Exception:
          pass
    
    print(f"  [DEBUG] Total BOXIOC markers found: {boxioc_count}")
  
  # *.results artifacts - only if we don't have final URLs
  if not final_urls:
    collected = []
    for res in result_dir.glob("*.results"):
      if not res.is_dir(): continue
      for name in ("urls.json","active_urls.json"):
        p = res / name
        if p.exists():
          try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, list):
              for u in data: urls.add(str(u))
            elif isinstance(data, dict):
              for v in data.values():
                if isinstance(v, list):
                  for u in v: urls.add(str(u))
          except Exception: pass
      for name in ("snippets.json","analysis.log"):
        p = res / name
        if p.exists():
          try: collected.append(p.read_text(encoding="utf-8", errors="ignore"))
          except Exception: pass
    for txt in collected:
      for m in GENERIC_URL_RE.finditer(txt): urls.add(m.group(0).strip('"\'')) 
      for em in EMAIL_RE.findall(txt): emails.add(em)
  
  # Prioritize final URLs over partial ones
  if final_urls:
    return final_urls, emails
  else:
    return urls, emails

def extract_iocs_quick(text: str) -> Tuple[Set[str], Set[str]]:
  return (set(m.group(0) for m in GENERIC_URL_RE.finditer(text)),
          set(EMAIL_RE.findall(text)))

def is_http_like(u: str) -> bool:
  return bool(re.match(r'(?i)^(https?:\/\/|\/\/|mailto:)', u.strip()))

def looks_local(u: str) -> bool:
  s = u.strip().strip('"\';')
  if LOCAL_JS_FILENAME_RE.match(s): return True
  if '/' not in s and s.count('.')>=1 and not s.lower().startswith(('http','//','mailto')): return True
  return False

def parse_js_url_construction(js_code: str, emails: set) -> str:
  """Parse JavaScript like: window.location.href = atob("aH"+`R0`+'cH'+...)+i;"""
  try:
    # Look for atob() call with concatenated base64 parts
    atob_match = re.search(r'atob\s*\(\s*([^)]+)\s*\)', js_code)
    if not atob_match:
      return None
    
    atob_content = atob_match.group(1)
    print(f"    [DEBUG] atob content: {atob_content}")
    
    # Extract all quoted strings and combine them
    # Handle both single quotes, double quotes, and backticks
    b64_parts = []
    for match in re.finditer(r'["\']([^"\']*)["\']|`([^`]*)`', atob_content):
      part = match.group(1) if match.group(1) is not None else match.group(2)
      if part:
        # Remove any escape characters that might interfere
        part = part.replace('\\', '')
        b64_parts.append(part)
    
    if not b64_parts:
      return None
    
    combined_b64 = ''.join(b64_parts)
    print(f"    [DEBUG] Combined base64: {combined_b64}")
    
    # Decode the base64
    decoded_url = base64.b64decode(combined_b64).decode('utf-8', errors='ignore')
    print(f"    [DEBUG] Decoded base URL: {decoded_url}")
    
    # Look for variable addition (like +i)
    var_match = re.search(r'\+\s*(\w+)\s*;?', js_code)
    if var_match:
      var_name = var_match.group(1)
      print(f"    [DEBUG] Found variable to append: {var_name}")
      print(f"    [DEBUG] Available emails: {emails}")
      
      # For XOR patterns, variables often contain the email with $ prefix
      if emails:
        # Use the first email we found and add $ prefix to match original XOR pattern
        email = list(emails)[0]
        email_with_prefix = '$' + email
        print(f"    [DEBUG] Appending email: {email_with_prefix}")
        return decoded_url + email_with_prefix
    else:
      print(f"    [DEBUG] No variable to append found in: {js_code}")
    
    return decoded_url
    
  except Exception as e:
    print(f"    [DEBUG] Failed to parse JS URL construction: {e}")
    return None

def parse_dynamic_execution_url(js_code: str, emails: set = None) -> str:
  """Parse dynamic execution code for URLs like fetch([...].join("")) or simple strings"""
  try:
    # Check for fetch() with array join pattern: fetch([...].join(""))
    # Handle both escaped \" and unescaped " quotes
    fetch_array_match = re.search(r'fetch\s*\(\s*\[([^\]]+)\]\.join\s*\(\s*\\?["\']\\?["\']?\s*\)', js_code)
    if fetch_array_match:
      array_content = fetch_array_match.group(1)
      print(f"    [DEBUG] Found fetch array pattern: [{array_content[:50]}...]")
      
      # Extract quoted strings from the array (handle both escaped \" and unescaped quotes)
      url_chars = []
      for match in re.finditer(r'\\?["\']([^"\'\\]*)\\?["\']', array_content):
        char = match.group(1)
        if char:
          url_chars.append(char.replace('\\', ''))  # Remove escape characters
      
      if url_chars:
        reconstructed_url = ''.join(url_chars)
        print(f"    [DEBUG] Reconstructed fetch URL: {reconstructed_url}")
        if 'http' in reconstructed_url:
          return reconstructed_url
    else:
      print(f"    [DEBUG] No fetch array pattern found in: {js_code[:100]}...")
    
    # Check for URL + variable pattern (e.g., "https://example.com" + varname)
    url_concat_match = re.search(r'["\']([^"\']*https?://[^"\']*)["\']?\s*\+\s*([a-zA-Z_][a-zA-Z0-9_]*)', js_code)
    if url_concat_match:
      base_url = url_concat_match.group(1).replace('\\', '')  # Remove escape characters
      var_name = url_concat_match.group(2)
      print(f"    [DEBUG] Found URL concatenation: {base_url} + {var_name}")
      
      # If we have emails available, append the first one with $ prefix
      if emails:
        email = list(emails)[0]
        email_with_prefix = '$' + email
        print(f"    [DEBUG] Appending email: {email_with_prefix}")
        return base_url + email_with_prefix
      else:
        return base_url
    
    # First, try to find any direct URL patterns
    direct_url_match = re.search(r'https?://[^\s"\'`]+', js_code)
    if direct_url_match:
      return direct_url_match.group(0)
    
    # Look for array join patterns like ["h","t","t",...].join("") or [\"h\",\"t\",\"t\",...].join(\"\")
    array_pattern = r'\[([^\]]+)\]\.join\([\\]?["\'][\\]?["\']?\)'
    match = re.search(array_pattern, js_code)
    
    if match:
      array_content = match.group(1)
      
      # Extract quoted strings from the array (handle both escaped and unescaped quotes)
      char_parts = []
      for char_match in re.finditer(r'[\\]?["\']([^"\'\\]*)[\\]?["\']', array_content):
        char_parts.append(char_match.group(1))
      
      if char_parts:
        url = ''.join(char_parts)
        if is_http_like(url):
          return url
    
    # Look for string concatenation patterns like "http" + "s://" + ...
    if '+' in js_code and ('http' in js_code or 'ftp' in js_code):
      # Try to extract and combine quoted parts
      parts = []
      for part_match in re.finditer(r'["\']([^"\']*)["\']', js_code):
        parts.append(part_match.group(1))
      if parts:
        combined = ''.join(parts)
        if is_http_like(combined):
          return combined
    
    return None
    
  except Exception as e:
    print(f"    [DEBUG] Failed to parse dynamic execution URL: {e}")
    return None

def normalize(u: str) -> str:
  return u.strip().strip('"\';')

def should_keep(u: str, ignore_hosts: Iterable[str], allow_relative: bool) -> bool:
  if not u: return False
  s = normalize(u); low = s.lower()
  for h in ignore_hosts:
    if h.lower() in low: return False
  if s.lower().startswith('mailto:'): return True
  if s.startswith('//'): return True  # keep protocol-relative
  if is_http_like(s): return True
  if looks_local(s): return False
  return False

def main():
  ap = argparse.ArgumentParser(description="box-js dynamic SVG extractor with URL/ActiveX/WScript sink hooks")
  ap.add_argument("-i","--input", required=True, help="Input SVG file or directory")
  ap.add_argument("-o","--out", default="boxjs_out", help="Directory to save box-js outputs")
  ap.add_argument("-t","--timeout", type=int, default=BOXJS_TIMEOUT_DEFAULT, help="Timeout per box-js analysis (seconds)")
  ap.add_argument("--keep-temp", action="store_true", help="Keep temporary JS/prelude/results")
  ap.add_argument("--blocklist-out", help="Write final URL blocklist to file")
  ap.add_argument("--emails-out", help="Write final emails to file")
  ap.add_argument("--ignore-host", action="append", help="Extra host substrings to ignore (repeatable)")
  ap.add_argument("--allow-relative", action="store_true", help="Keep relative URLs (default keeps protocol-relative // only)")
  ap.add_argument("--mask-emails", action="store_true", help="Hide email addresses in console output for privacy")
  args = ap.parse_args()

  ignore_hosts = set(args.ignore_host or [])
  ignore_hosts.add("w3.org")  # default ignore

  inp = Path(args.input).expanduser().resolve()
  out_root = Path(args.out).expanduser().resolve(); out_root.mkdir(parents=True, exist_ok=True)

  svgs = find_svgs(inp)
  if not svgs:
    print("[!] No SVG files found.", file=sys.stderr); sys.exit(2)

  tmp = Path(tempfile.mkdtemp(prefix="boxjs_svg_"))
  all_urls, all_emails = set(), set()
  failed_files, processed_files, successful_files = [], [], []

  try:
    prelude_path = write_prelude(tmp)
    for svg in svgs:
      print(f"\n=== Processing: {svg} ===")
      processed_files.append(svg.name)
      file_had_urls_before = len(all_urls)
      
      try: raw = svg.read_text(encoding="utf-8", errors="replace")
      except Exception as e: 
        print(f"[!] Failed to read {svg}: {e}", file=sys.stderr)
        failed_files.append((svg.name, f"Failed to read: {e}"))
        continue

      scripts = extract_scripts(raw)
      quick_u, quick_e = extract_iocs_quick(raw); all_emails.update(quick_e)

      if not scripts:
        print("  (no <script> blocks found) - scanning raw for IOCs")
        kept = [normalize(u) for u in quick_u if should_keep(u, ignore_hosts, args.allow_relative)]
        if kept:
          print("  URLs found by regex in raw file:")
          for u in sorted(set(kept)): print("   ", u); all_urls.add(u)
        continue

      base = svg.stem
      js_dir = tmp / base
      js_path = write_temp_js(scripts, js_dir, base)
      result_dir = out_root / f"{svg.name}.boxjs_results"
      if result_dir.exists():
        i=1
        while True:
          alt = out_root / f"{svg.name}.boxjs_results.{i}"
          if not alt.exists(): result_dir=alt; break
          i+=1

      print(f"  Wrote temp JS -> {js_path}")
      print(f"  Running box-js (timeout {args.timeout}s) with sink hooks (ActiveX/WScript included)...")
      ok,_ = run_boxjs(js_path, result_dir, prelude_path, args.timeout)
      if not ok: print("  [!] box-js returned non-zero or timed out. See logs:", result_dir)
      else: print("  [+] box-js finished. Results in:", result_dir)

      urls, emails = gather_results(result_dir, quick_e)
      js_text = js_path.read_text(encoding="utf-8", errors="replace")
      u_js, e_js = extract_iocs_quick(js_text); 
      u_raw, e_raw = quick_u, quick_e; 
      
      # Separate final URLs from partial ones
      final_complete_urls = set()
      partial_urls = set()
      
      # Check if gather_results returned final URLs (they have priority)
      for u in urls:
        if is_http_like(u) and should_keep(u, ignore_hosts, args.allow_relative):
          final_complete_urls.add(normalize(u))
      
      # Add any additional URLs from JS/raw content only if no final URLs found
      if not final_complete_urls:
        for u in u_js.union(u_raw):
          if should_keep(u, ignore_hosts, args.allow_relative):
            if is_http_like(u):
              final_complete_urls.add(normalize(u))
            else:
              partial_urls.add(normalize(u))

      kept_emails = { e for e in emails.union(e_js).union(e_raw) if EMAIL_RE.search(e) }

      if final_complete_urls:
        print("  *** FINAL COMPLETE URLs FOUND ***:")
        for u in sorted(final_complete_urls): 
          print(f"    → {u}")
      elif partial_urls:
        print("  Partial URLs/components found:")
        for u in sorted(partial_urls): print("   ", u)
      else:
        print("  (no URLs found after filtering)")

      if kept_emails:
        print("  Emails found:")
        for e in sorted(kept_emails): 
          display_email = mask_email(e) if args.mask_emails else e
          print("   ", display_email)
      else:
        print("  (no emails found)")

      all_urls.update(final_complete_urls); all_emails.update(kept_emails)

      # Track if this file was successful (extracted any URLs)
      file_had_urls_after = len(all_urls)
      if file_had_urls_after > file_had_urls_before or final_complete_urls:
        successful_files.append(svg.name)
      else:
        # File was processed but no URLs extracted
        if scripts:
          failed_files.append((svg.name, "No URLs extracted from scripts"))
        elif not quick_u:
          failed_files.append((svg.name, "No scripts or URLs found"))

      if not args.keep_temp:
        try: shutil.rmtree(js_dir)
        except Exception: pass

    print("\n\n=== FINAL ANALYSIS SUMMARY ===")
    if all_urls:
      print(f"\n🎯 COMPLETE URLs EXTRACTED ({len(all_urls)} total):")
      print("=" * 60)
      for u in sorted(all_urls): 
        print(f"  → {u}")
      print("=" * 60)
    else:
      print("\n❌ No complete URLs discovered across processed files.")
      print("   (This may indicate the obfuscation wasn't fully resolved)")
    
    if all_emails:
      print(f"\n📧 Email addresses found ({len(all_emails)} total):")
      for e in sorted(all_emails): 
        display_email = mask_email(e) if args.mask_emails else e
        print(f"  → {display_email}")
    else:
      print("\n(No email addresses discovered)")

    # Show any unparsed FINALURL content that couldn't be processed
    unparsed_content = []
    try:
      for svg in svgs:
        result_dir = out_root / f"{svg.name}.boxjs_results"
        if result_dir.exists():
          for results_file in result_dir.glob("*.boxjs_results*"):
            try:
              content = results_file.read_text(encoding="utf-8", errors="replace")
              for line in content.split('\n'):
                if '[FINALURL]' in line and 'Script output:' in line:
                  # Extract the actual finalurl content
                  finalurl_part = line.split('[FINALURL]', 1)[1].strip()
                  if finalurl_part and not any(url in finalurl_part for url in all_urls):
                    # This FINALURL content wasn't successfully parsed into a complete URL
                    unparsed_content.append(finalurl_part)
            except Exception:
              continue
    except Exception:
      pass
    
    if unparsed_content:
      print(f"\n⚠️  UNPARSED FINALURL content ({len(unparsed_content)} items):")
      print("   (These were detected but couldn't be fully parsed into complete URLs)")
      for i, content in enumerate(sorted(set(unparsed_content)), 1):
        content_preview = content[:100] + "..." if len(content) > 100 else content
        print(f"  {i}. {content_preview}")

    # Show processing summary
    total_processed = len(processed_files)
    total_successful = len(successful_files)
    total_failed = len(failed_files)
    
    print(f"\n📊 PROCESSING SUMMARY:")
    print(f"  • Total files processed: {total_processed}")
    print(f"  • Successfully extracted URLs: {total_successful}")
    print(f"  • Failed to extract URLs: {total_failed}")
    
    if failed_files:
      print(f"\n❌ FILES THAT COULDN'T BE PARSED ({len(failed_files)} files):")
      for i, (filename, reason) in enumerate(failed_files, 1):
        print(f"  {i}. {filename} - {reason}")

    if args.blocklist_out:
      Path(args.blocklist_out).write_text("\n".join(sorted(all_urls))+("\n" if all_urls else ""), encoding="utf-8")
      print(f"\nWrote URL blocklist -> {args.blocklist_out}")
    if args.emails_out:
      Path(args.emails_out).write_text("\n".join(sorted(all_emails))+("\n" if all_emails else ""), encoding="utf-8")
      print(f"Wrote email list -> {args.emails_out}")

  finally:
    if not args.keep_temp:
      try: shutil.rmtree(tmp)
      except Exception: pass

if __name__ == "__main__":
  main()
