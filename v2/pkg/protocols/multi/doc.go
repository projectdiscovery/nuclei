package multi

// multi is a wrapper protocol Request that allows multiple protocols requests to be executed
// multi protocol is just a wrapper so it should/does not include any protocol specific code

// Implementation:
// when template is unmarshalled, if it uses more than one protocol, it will be converted to a multi protocol
// and the order of the protocols will be preserved as they were in the template and are stored in Request.Queue
// when template is compiled , we iterate over queue and compile all the requests in the queue

// Execution:
// when multi protocol template is executed , all protocol requests present in Queue are executed in order
// and dynamic values extracted from previous protocols are passed to next protocol in queue

// Other Methods:
// Such templates are usually used when a particular vulnerability requires more than one protocol to be executed
// and in such cases the final result is core of the logic hence all methods such as
// Ex:  MakeResultEventItem, MakeResultEvent, GetCompiledOperators
// are not implemented in multi protocol and just call the same method on last protocol in queue
