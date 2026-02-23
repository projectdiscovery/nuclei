import re

# Nuclei XSS Context Analyzer - ISAAC-5838 Implementation
# Logic: Identifies where the input lands in HTML to suggest the best payload.

def analyze_xss_context(html_snippet):
    contexts = {
        "attribute": r'=\s*["\']([^"\'>]*)$',  # Inside href="...", src="..."
        "script": r'<script[^>]*>([\s\S]*?)$',    # Inside <script> tags
        "comment": r'<!--([\s\S]*?)$',            # Inside <!-- comments -->
        "tag_body": r'>([^<]*)$'                  # Between <div>...</div>
    }
    
    for context_name, pattern in contexts.items():
        if re.search(pattern, html_snippet, re.IGNORECASE):
            return {"context": context_name, "found": True}
            
    return {"context": "raw_html", "found": False}

# Example use:
# print(analyze_xss_context('<div class="'))
