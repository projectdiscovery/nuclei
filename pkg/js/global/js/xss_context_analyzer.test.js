// xss_context_analyzer.test.js
// Focused regression tests for the four edge cases in issue #7086.
// Run with: node xss_context_analyzer.test.js

'use strict';

var analyzer = require('./xss_context_analyzer');

var passed = 0;
var failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log('  PASS:', message);
    passed++;
  } else {
    console.error('  FAIL:', message);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  var ok = actual === expected;
  if (ok) {
    console.log('  PASS:', message);
    passed++;
  } else {
    console.error('  FAIL:', message, '| expected:', expected, '| got:', actual);
    failed++;
  }
}

console.log('\n=== Issue #7086: XSS Context Analyzer Edge Cases ===\n');

// ---------------------------------------------------------------------------
// 1. javascript: URI should be classified as ContextScript
// ---------------------------------------------------------------------------
console.log('1. javascript: URI classification');

// Basic case: standard lowercase
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'href', 'javascript:alert(nucleiXSScanary)'),
  analyzer.ContextScript,
  'href="javascript:alert(...)" should be ContextScript'
);

// Protocol case variation: mixed case (browsers normalize before executing)
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'href', 'JavaScript:alert(nucleiXSScanary)'),
  analyzer.ContextScript,
  'href="JavaScript:..." mixed-case should still be ContextScript'
);

// Protocol case variation: all caps
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'href', 'JAVASCRIPT:alert(nucleiXSScanary)'),
  analyzer.ContextScript,
  'href="JAVASCRIPT:..." uppercase should still be ContextScript'
);

// vbscript: URI (IE legacy vector, must not be missed)
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'href', 'vbscript:alert(nucleiXSScanary)'),
  analyzer.ContextScript,
  'href="vbscript:..." should be ContextScript'
);

// Leading whitespace (browsers ignore leading whitespace before scheme)
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'href', '  javascript:alert(nucleiXSScanary)'),
  analyzer.ContextScript,
  'href with leading spaces before javascript: should be ContextScript'
);

// Confirm a plain URL is NOT ContextScript (regression guard)
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'href', 'https://example.com/nucleiXSScanary'),
  analyzer.ContextAttribute,
  'href with https: URL should remain ContextAttribute'
);

// ---------------------------------------------------------------------------
// 2. <script type="application/json"> should NOT be ContextScript
// ---------------------------------------------------------------------------
console.log('\n2. Non-executable <script> type classification');

equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', null, null, 'application/json'),
  analyzer.ContextUnknown,
  '<script type="application/json"> should be ContextUnknown (not executable)'
);

equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', null, null, 'application/ld+json'),
  analyzer.ContextUnknown,
  '<script type="application/ld+json"> should be ContextUnknown (not executable)'
);

equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', null, null, 'text/plain'),
  analyzer.ContextUnknown,
  '<script type="text/plain"> should be ContextUnknown (not executable)'
);

// Type with charset parameter should still be recognized
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', null, null, 'application/json; charset=utf-8'),
  analyzer.ContextUnknown,
  '<script type="application/json; charset=utf-8"> should be ContextUnknown'
);

// Case-insensitive type matching
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', null, null, 'Application/JSON'),
  analyzer.ContextUnknown,
  '<script type="Application/JSON"> mixed case should be ContextUnknown'
);

// Executable script (no type) must still be ContextScript
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', null, null, ''),
  analyzer.ContextScript,
  '<script> with empty type should be ContextScript (executable)'
);

equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', null, null, 'text/javascript'),
  analyzer.ContextScript,
  '<script type="text/javascript"> should be ContextScript'
);

// ---------------------------------------------------------------------------
// 3. Case-insensitive reflection detection
// ---------------------------------------------------------------------------
console.log('\n3. Case-insensitive reflection detection');

// Canary reflected as-is
assert(
  analyzer.isReflected('<div>nucleiXSScanary</div>', 'nucleiXSScanary'),
  'Exact-case canary should be detected'
);

// Canary uppercased by server
assert(
  analyzer.isReflected('<div>NUCLEIXSSCANARY</div>', 'nucleiXSScanary'),
  'Uppercased canary should be detected (case-insensitive)'
);

// Canary mixed-case
assert(
  analyzer.isReflected('<div>NuClEiXsScAnArY</div>', 'nucleiXSScanary'),
  'Mixed-case canary should be detected'
);

// Canary entity-encoded: &#110;ucleIXSScanary  (n -> &#110;)
assert(
  analyzer.isReflected('<div>&#110;ucleIXSScanary</div>', 'nucleiXSScanary'),
  'Entity-encoded canary (&#110; for n) should be detected after normalization'
);

// Canary with &amp; instead of &
assert(
  analyzer.isReflected('<div>nucleiXSScan&amp;ary</div>', 'nucleiXSScan&ary'),
  'Entity-encoded & in canary should be detected'
);

// Absent canary must NOT match (regression guard)
assert(
  !analyzer.isReflected('<div>something else entirely</div>', 'nucleiXSScanary'),
  'Non-reflected canary must NOT be detected'
);

// Empty inputs
assert(
  !analyzer.isReflected('', 'nucleiXSScanary'),
  'Empty body must not match'
);
assert(
  !analyzer.isReflected('<html></html>', ''),
  'Empty canary must not match'
);

// ---------------------------------------------------------------------------
// 4. srcdoc attribute should be ContextSrcdoc
// ---------------------------------------------------------------------------
console.log('\n4. srcdoc attribute classification');

equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'srcdoc', '<script>nucleiXSScanary</script>'),
  analyzer.ContextSrcdoc,
  'srcdoc attribute should be ContextSrcdoc'
);

// Case-insensitive attribute name
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'SRCDOC', 'nucleiXSScanary'),
  analyzer.ContextSrcdoc,
  'SRCDOC (uppercase) should also be ContextSrcdoc'
);

// Plain href is not srcdoc
equal_test(
  analyzer.classifyContext(null, 'nucleiXSScanary', 'href', 'https://example.com/nucleiXSScanary'),
  analyzer.ContextAttribute,
  'href with plain URL must not be ContextSrcdoc'
);

// ---------------------------------------------------------------------------
// 5. Helper unit tests
// ---------------------------------------------------------------------------
console.log('\n5. Helper function unit tests');

assert(analyzer.isJavaScriptURI('javascript:alert(1)'), 'isJavaScriptURI: javascript:');
assert(analyzer.isJavaScriptURI('JAVASCRIPT:alert(1)'), 'isJavaScriptURI: JAVASCRIPT:');
assert(analyzer.isJavaScriptURI('  javascript:alert(1)'), 'isJavaScriptURI: leading spaces');
assert(analyzer.isJavaScriptURI('vbscript:msgbox(1)'), 'isJavaScriptURI: vbscript:');
assert(!analyzer.isJavaScriptURI('https://example.com'), 'isJavaScriptURI: https is not JS URI');
assert(!analyzer.isJavaScriptURI(''), 'isJavaScriptURI: empty string is false');

assert(analyzer.isNonExecutableScriptType('application/json'), 'isNonExec: application/json');
assert(analyzer.isNonExecutableScriptType('Application/JSON'), 'isNonExec: case-insensitive');
assert(analyzer.isNonExecutableScriptType('application/json; charset=utf-8'), 'isNonExec: with params');
assert(!analyzer.isNonExecutableScriptType('text/javascript'), 'isNonExec: text/javascript is executable');
assert(!analyzer.isNonExecutableScriptType(''), 'isNonExec: empty type is executable');

assert(analyzer.isSrcdocAttribute('srcdoc'), 'isSrcdoc: srcdoc');
assert(analyzer.isSrcdocAttribute('SRCDOC'), 'isSrcdoc: SRCDOC uppercase');
assert(!analyzer.isSrcdocAttribute('href'), 'isSrcdoc: href is not srcdoc');
assert(!analyzer.isSrcdocAttribute('src'), 'isSrcdoc: src is not srcdoc');

var norm = analyzer.normalizeForReflection;
assert(norm('&lt;') === '<', 'normalizeForReflection: &lt; -> <');
assert(norm('&amp;') === '&', 'normalizeForReflection: &amp; -> &');
assert(norm('&#110;') === 'n', 'normalizeForReflection: &#110; -> n');
assert(norm('&#x6E;') === 'n', 'normalizeForReflection: &#x6E; -> n');
assert(norm('HELLO') === 'hello', 'normalizeForReflection: lowercases');

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
function equal_test(actual, expected, message) {
  assertEqual(actual, expected, message);
}

console.log('\n=== Results ===');
console.log('Passed:', passed);
console.log('Failed:', failed);
if (failed > 0) {
  process.exit(1);
}
