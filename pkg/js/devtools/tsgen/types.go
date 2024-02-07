package tsgen

// Define a struct to hold information about your TypeScript entities
type Entity struct {
	Name          string
	Value         string
	Type          string // "class", "function", or "object" or "interface" or "const"
	Description   string
	Example       string    // this will be part of description with @example jsdoc tag
	Class         Class     // if Type == "class"
	Function      Function  // if Type == "function"
	Object        Interface // if Type == "object"
	IsConstructor bool      // true if this is a constructor function
}

// Class represents a TypeScript class data structure
type Class struct {
	Properties  []Property
	Methods     []Method
	Constructor Function
}

// Function represents a TypeScript function data structure
// If CanFail is true, the function returns a Result<T, E> type
// So modify the function signature to return a Result<T, E> type in this case
type Function struct {
	Parameters []Parameter
	Returns    string
	CanFail    bool
	ReturnStmt string
}

type Interface struct {
	Properties []Property
}

// Method represents a TypeScript method data structure
// If CanFail is true, the method returns a Result<T, E> type
// So modify the method signature to return a Result<T, E> type in this case
type Method struct {
	Name        string
	Description string
	Parameters  []Parameter
	Returns     string
	CanFail     bool
	ReturnStmt  string
}

// Property represent class or object property
type Property struct {
	Name        string
	Type        string
	Description string
}

// Parameter represents function or method parameter
type Parameter struct {
	Name string
	Type string
}
