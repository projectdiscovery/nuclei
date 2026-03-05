# XSS Context Analyzer 修复计划

## Issue #7086 描述的问题

### 1. javascript: URI 误分类
**问题**: `javascript:` URI 被错误分类为 HTML 文本而不是 JavaScript 上下文

**测试用例**:
```html
<a href="javascript:alert('XSS')">Click</a>
```

**当前行为**: 分类为 HTMLText
**期望行为**: 分类为 JavaScript/Script 上下文

### 2. JSON `<script>` blocks 误分类
**问题**: JSON 数据在 script 标签中被错误分析

**测试用例**:
```html
<script type="application/json">{"user": "<script>alert(1)</script>"}</script>
```

**当前行为**: 可能分类为 Script
**期望行为**: 识别为 JSON 数据，不执行 XSS payload

## 修复方案

### 文件 1: pkg/fuzz/analyzers/xss/context.go

添加特殊上下文检测：

```go
// detectJavascriptURI checks for javascript: URI scheme
func detectJavascriptURI(token html.Token) bool {
    if token.DataKey == "href" || token.DataKey == "src" {
        return strings.HasPrefix(strings.TrimSpace(token.Data), "javascript:")
    }
    return false
}

// detectJSONScript checks for JSON script blocks
func detectJSONScript(token html.Token) bool {
    if token.Data == "script" {
        for _, attr := range token.Attr {
            if attr.Key == "type" && 
               (attr.Val == "application/json" || attr.Val == "application/ld+json") {
                return true
            }
        }
    }
    return false
}
```

### 文件 2: pkg/fuzz/analyzers/xss/analyzer.go

更新分析逻辑：

```go
func (a *Analyzer) analyze(response string) (*Result, error) {
    // ... existing code ...
    
    // Check for javascript: URI
    if a.detectJavascriptURI(token) {
        result.Context = ContextJavascriptURI
        result.SkipAnalysis = true  // Skip or use special payloads
        return result, nil
    }
    
    // Check for JSON script blocks
    if a.detectJSONScript(token) {
        result.Context = ContextJSON
        result.SkipAnalysis = true  // Not an XSS vector
        return result, nil
    }
    
    // ... rest of analysis ...
}
```

### 文件 3: pkg/fuzz/analyzers/xss/types.go

添加新上下文类型：

```go
const (
    ContextHTMLText        ContextType = "html-text"
    ContextAttribute       ContextType = "attribute"
    ContextScript          ContextType = "script"
    ContextStyle           ContextType = "style"
    ContextHTMLComment     ContextType = "html-comment"
    ContextJSON            ContextType = "json"           // NEW
    ContextJavascriptURI   ContextType = "javascript-uri" // NEW
    ContextNone            ContextType = "none"
)
```

## 测试用例

### context_test.go

```go
func TestDetectJavascriptURI(t *testing.T) {
    tests := []struct {
        name     string
        html     string
        expected bool
    }{
        {"javascript href", `<a href="javascript:alert(1)">`, true},
        {"javascript src", `<script src="javascript:alert(1)">`, true},
        {"http href", `<a href="http://example.com">`, false},
        {"javascript in text", `text with javascript: word`, false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}

func TestDetectJSONScript(t *testing.T) {
    tests := []struct {
        name     string
        html     string
        expected bool
    }{
        {"JSON script", `<script type="application/json">{}</script>`, true},
        {"LD+JSON", `<script type="application/ld+json">{}</script>`, true},
        {"Regular script", `<script>alert(1)</script>`, false},
        {"JS script", `<script type="text/javascript">`, false},
    }
}
```

## 实施步骤

1. ✅ 创建分支 `fix/xss-context-edge-cases`
2. ⏳ 修改 `types.go` - 添加新上下文类型
3. ⏳ 修改 `context.go` - 添加检测方法
4. ⏳ 修改 `analyzer.go` - 更新分析逻辑
5. ⏳ 添加测试用例
6. ⏳ 运行测试
7. ⏳ 提交 PR

## ETA

- 代码修改：2-3 小时
- 测试：1 小时
- PR 提交：今天内
