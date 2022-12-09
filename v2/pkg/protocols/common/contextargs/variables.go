package contextargs

// GenerateVariables from context args
func GenerateVariables(ctx *Context) map[string]interface{} {
	vars := map[string]interface{}{
		"Ip": ctx.MetaInput.CustomIP,
	}
	return vars
}
