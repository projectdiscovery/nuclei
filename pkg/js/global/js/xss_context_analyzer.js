// xss_context_analyzer.js
// Fixes for XSS context classification edge cases described in issue #7086:
// 1. javascript: URIs must be treated as executable script context (ContextScript)
// 2. <script type="application/json"> (and similar non-executable types) must NOT be treated as executable
// 3. Reflection detection must be case-insensitive and entity-normalized
// 4. srcdoc attributes must be treated as HTML injection context

// Context constants
var ContextUnknown   = 'ContextUnknown';
var ContextHTML      = 'ContextHTML';
var ContextAttribute = 'ContextAttribute';
var ContextScript    = 'ContextScript';
var ContextStyle     = 'ContextStyle';
var ContextSrcdoc    = 'ContextSrcdoc';  // NEW: full HTML injection via srcdoc

// NON_EXECUTABLE_SCRIPT_TYPES lists MIME types for <script> tags that browsers
// do NOT execute. Content inside these blocks is data, not code.
// Reference: https://html.spec.whatwg.org/multipage/scripting.html#attr-script-type
// NOTE: 'module' is intentionally excluded — <script type="module"> IS executable
// in all modern browsers (deferred, strict mode, but still runs JS).
var NON_EXECUTABLE_SCRIPT_TYPES = [
  'application/json',
  'application/ld+json',
  'text/plain',
  'text/template',
  'text/x-template',
  'text/x-handlebars-template',
  'text/ng-template',
];

// EXECUTABLE_URI_SCHEMES lists URI scheme prefixes that result in script execution
// when used in href/src/action/etc. attributes.
// Also includes data: URIs that embed HTML documents.
var EXECUTABLE_URI_SCHEMES = [
  'javascript:',
  'vbscript:',      // IE legacy, still relevant for completeness
  'data:text/html', // <iframe src="data:text/html,..."> executes embedded scripts
  'data:application/xhtml+xml', // same as above, XHTML variant
];

/**
 * normalizeForReflection decodes common HTML entity encodings and lowercases
 * a string so that reflection detection is not fooled by case transforms
 * or entity encoding in the response.
 *
 * WHY: Servers may reflect input as &amp;alert or &#97;lert or ALert —
 * all of which represent the same payload. Without normalization, a naive
 * string-equality check would miss them.
 */
function normalizeForReflection(str) {
  if (!str) return '';
  // Decode named HTML entities for common XSS characters
  var s = str
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#39;/gi, "'")
    .replace(/&#x2F;/gi, '/')
    .replace(/&#47;/gi, '/')
    // Decode decimal numeric entities WITH semicolon: &#97; -> 'a'
    .replace(/&#(\d+);/gi, function(_, dec) {
      return String.fromCharCode(parseInt(dec, 10));
    })
    // Decode decimal numeric entities WITHOUT semicolon: &#97 -> 'a'
    // Browsers accept these in certain contexts (e.g. &#110ucleXSS)
    .replace(/&#(\d+)(?=[^;0-9]|$)/gi, function(_, dec) {
      return String.fromCharCode(parseInt(dec, 10));
    })
    // Decode hex numeric entities like &#x61; -> 'a'
    .replace(/&#x([0-9a-f]+);/gi, function(_, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    });
  return s.toLowerCase();
}

/**
 * isNonExecutableScriptType returns true if the given <script> type attribute
 * value indicates the block is NOT executable JavaScript.
 *
 * WHY: <script type="application/json"> is commonly used to embed structured
 * data in HTML. Its content is never executed by the browser. Classifying it
 * as ContextScript causes false positives — a reflected payload inside a JSON
 * block is not exploitable as XSS.
 *
 * @param {string} typeAttr - the raw value of the type= attribute
 * @returns {boolean}
 */
function isNonExecutableScriptType(typeAttr) {
  if (!typeAttr) return false;
  // Normalize: trim whitespace, lowercase, strip parameters (e.g. charset)
  var normalized = typeAttr.trim().toLowerCase().split(';')[0].trim();
  for (var i = 0; i < NON_EXECUTABLE_SCRIPT_TYPES.length; i++) {
    if (normalized === NON_EXECUTABLE_SCRIPT_TYPES[i]) {
      return true;
    }
  }
  return false;
}

/**
 * isJavaScriptURI returns true if the given attribute value is a
 * javascript:, vbscript:, or data: URI that causes script execution
 * when the browser navigates to the href/src/action value.
 *
 * WHY: href="javascript:alert(1)" is a classic XSS vector. If the context
 * analyzer only looks at the fact that the canary appears inside an attribute
 * value, it will classify this as ContextAttribute. But the attribute VALUE
 * is itself executable, so the correct classification is ContextScript.
 *
 * Normalization handles:
 *   - Case variations:     JavaScript: -> javascript:
 *   - Leading whitespace:  \tjavascript: -> javascript:
 *   - URL encoding:        %6aavascript: -> javascript: (browsers decode before scheme check)
 *
 * @param {string} attrValue - the raw attribute value string
 * @returns {boolean}
 */
function isJavaScriptURI(attrValue) {
  if (!attrValue) return false;
  // Browsers strip leading whitespace/control chars before parsing the URI scheme
  var trimmed = attrValue.replace(/^[\s\t\n\r\0]+/, '');
  // Decode URL percent-encoding so %6aavascript: is caught
  var decoded = trimmed;
  try {
    decoded = decodeURIComponent(trimmed);
  } catch (_) {
    // decodeURIComponent throws on malformed sequences — fall back to trimmed
    decoded = trimmed.replace(/%([0-9a-f]{2})/gi, function(_, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }
  var normalized = decoded.toLowerCase();
  for (var i = 0; i < EXECUTABLE_URI_SCHEMES.length; i++) {
    if (normalized.indexOf(EXECUTABLE_URI_SCHEMES[i]) === 0) {
      return true;
    }
  }
  return false;
}

/**
 * isSrcdocAttribute returns true if the attribute name is srcdoc.
 *
 * WHY: The srcdoc attribute on <iframe> receives a full HTML document as its
 * value. Injection into srcdoc is equivalent to injecting into the document
 * body — any HTML including <script> tags will be parsed. It should be
 * classified as ContextSrcdoc (HTML injection), not plain ContextAttribute.
 *
 * @param {string} attrName - the attribute name, case-insensitive
 * @returns {boolean}
 */
function isSrcdocAttribute(attrName) {
  return attrName && attrName.trim().toLowerCase() === 'srcdoc';
}

/**
 * classifyContext determines the injection context for a reflected XSS canary
 * found in an HTML response fragment.
 *
 * Context classification drives which payloads nuclei will attempt:
 *   - ContextScript   -> direct JS execution payloads (alert(), etc.)
 *   - ContextSrcdoc   -> full HTML payloads
 *   - ContextAttribute-> attribute escape payloads (">...)
 *   - ContextStyle    -> CSS-based payloads
 *   - ContextHTML     -> tag injection payloads (<script>...)
 *   - ContextUnknown  -> fallback
 *
 * @param {string} fragment     - the HTML fragment surrounding the canary
 * @param {string} canary       - the canary string to locate
 * @param {string} attrName     - (optional) the attribute name in which canary appears
 * @param {string} attrValue    - (optional) the full attribute value
 * @param {string} scriptType   - (optional) the type= attribute of the enclosing <script>
 * @returns {string} one of the Context* constants
 */
function classifyContext(fragment, canary, attrName, attrValue, scriptType) {
  // --- 1. JSON / non-executable script blocks ---
  // Must be checked BEFORE the generic ContextScript check.
  if (scriptType !== undefined && scriptType !== null) {
    if (isNonExecutableScriptType(scriptType)) {
      return ContextUnknown;
    }
    return ContextScript;
  }

  // --- 2. Attribute context ---
  if (attrValue !== undefined && attrValue !== null) {
    // 2a. srcdoc attribute -> HTML injection context
    // Check BEFORE javascript: URI check — srcdoc content is HTML, not a URL.
    // "javascript:alert(1)" inside srcdoc is literal text, not an executable URI.
    if (isSrcdocAttribute(attrName)) {
      return ContextSrcdoc;
    }
    // 2b. javascript:/vbscript:/data: URI in attribute value -> executable context
    if (isJavaScriptURI(attrValue)) {
      return ContextScript;
    }
    // Generic attribute context
    return ContextAttribute;
  }

  // --- 3. Fallback: scan the fragment for contextual clues ---
  if (!fragment) return ContextUnknown;

  var frag = fragment.toLowerCase();

  // Inside an executable <script> block
  if (frag.indexOf('<script') !== -1) {
    var typeMatch = fragment.match(/<script[^>]+type\s*=\s*["']?([^"'\s>]+)["']?/i);
    if (typeMatch && isNonExecutableScriptType(typeMatch[1])) {
      return ContextUnknown;
    }
    return ContextScript;
  }

  // Inside a style block or attribute
  if (frag.indexOf('<style') !== -1 || frag.indexOf('style=') !== -1) {
    return ContextStyle;
  }

  // Inside a tag attribute — match both quoted and unquoted attribute values
  if (frag.match(/=["'][^"']*$/) || frag.match(/=\S*$/)) {
    // Check for javascript: in the attribute value portion
    var attrValMatch = fragment.match(/=\s*["']?([^"'\s>]*)/i);
    if (attrValMatch && isJavaScriptURI(attrValMatch[1])) {
      return ContextScript;
    }
    // Check for srcdoc
    if (/srcdoc\s*=/i.test(fragment)) {
      return ContextSrcdoc;
    }
    return ContextAttribute;
  }

  // Default: treat as HTML context
  return ContextHTML;
}

/**
 * isReflected returns true if the canary string appears in the response body,
 * using case-insensitive, entity-normalized comparison.
 *
 * @param {string} responseBody - full HTTP response body
 * @param {string} canary       - the injected canary string to search for
 * @returns {boolean}
 */
function isReflected(responseBody, canary) {
  if (!responseBody || !canary) return false;
  var normBody   = normalizeForReflection(responseBody);
  var normCanary = normalizeForReflection(canary);
  return normBody.indexOf(normCanary) !== -1;
}

// Export for use in nuclei JS runtime and tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    classifyContext: classifyContext,
    isReflected: isReflected,
    isJavaScriptURI: isJavaScriptURI,
    isNonExecutableScriptType: isNonExecutableScriptType,
    isSrcdocAttribute: isSrcdocAttribute,
    normalizeForReflection: normalizeForReflection,
    ContextUnknown: ContextUnknown,
    ContextHTML: ContextHTML,
    ContextAttribute: ContextAttribute,
    ContextScript: ContextScript,
    ContextStyle: ContextStyle,
    ContextSrcdoc: ContextSrcdoc,
  };
}
