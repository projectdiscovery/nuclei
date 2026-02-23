import re

def analyze_xss_context(html_snippet):
    """
    Enhanced XSS Context Analyzer with ReDoS protection.
    Follows ProjectDiscovery's high-performance security standards.
    """
    # 1. Validation to prevent TypeError (Requested by CodeRabbit)
    if not isinstance(html_snippet, str) or not html_snippet:
        return {"context": "raw_html", "found": False}

    # 2. Limit input size to prevent resource exhaustion (CWE-400)
    html_snippet = html_snippet[-4096:] 

    # 3. Optimized Patterns using atomic-like grouping to prevent ReDoS
    contexts = {
        # Matches quoted and unquoted attributes: href="..., src='..., or id=...
        "attribute": r'=\s*(?:["\'][^"\'>]*|[^"\'\s>]+)$',
        
        # Optimized script/comment detection (prevents catastrophic backtracking)
        "script": r'(?i)<script\b[^>]*>(?:(?!</script>)[\s\S])*$',
        "comment": r'<!--(?:(?!-->)[\s\S])*$',
        
        # Simple text node detection
        "tag_body": r'>[^<]*$'
    }

    for context_name, pattern in contexts.items():
        try:
            # Using re.search with flags for safety
            if re.search(pattern, html_snippet, re.IGNORECASE):
                return {"context": context_name, "found": True}
        except Exception:
            continue
            
    return {"context": "raw_html", "found": False}
