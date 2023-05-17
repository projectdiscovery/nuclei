// getDomainControllerName returns the domain controller
// name for a host.
//
// If the name is not empty, it is returned.
// Otherwise, the host is used to query the domain controller name.
// from SMB, etc.
function getDomainControllerName(name, host) {
  if (name != "") {
    return name;
  }

  const s = require("nuclei/libsmb");
  const sc = s.Client();
  var list = sc.ListSMBv2Metadata(host, 445);
  if (!list) {
    throw("No domain controller found");
  }
  if (list && list.DNSDomainName != "") {
    console.log("Got domain controller", list.DNSDomainName);
    return list.DNSDomainName;
  } 
}
