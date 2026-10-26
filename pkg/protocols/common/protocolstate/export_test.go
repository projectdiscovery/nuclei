package protocolstate

// SwapMySQLLocalFileRegistry replaces the mysql driver file registry hooks
// for a test and returns a func that restores them.
func SwapMySQLLocalFileRegistry(register, deregister func(string)) func() {
	oldRegister, oldDeregister := registerMySQLLocalFile, deregisterMySQLLocalFile
	registerMySQLLocalFile, deregisterMySQLLocalFile = register, deregister
	return func() {
		registerMySQLLocalFile, deregisterMySQLLocalFile = oldRegister, oldDeregister
	}
}
