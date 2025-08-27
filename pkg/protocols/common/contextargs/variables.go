package contextargs

// GenerateVariables from context args
func GenerateVariables(ctx *Context) map[string]interface{} {
	vars := map[string]interface{}{
		"ip": ctx.MetaInput.CustomIP,
	}
	return vars
}
