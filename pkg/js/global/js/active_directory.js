// getDomainControllerName returns the domain controller
// name for a host.
//
// If the name is not empty, it is returned.
// Otherwise, the host is used to query the domain controller name.
// from SMB, LDAP, etc
function getDomainControllerName(name, host) {
  if (name != "") {
    return name;
  }

  // First try LDAP and then SMB
  try {
    var name = getDomainControllerNameByLDAP(host);
    if (name != "") {
      return name;
    }
  } catch (e) {
    console.log("[ldap] Error getting domain controller name", e);
  }

  try {
    var name = getDomainControllerNameBySMB(host);
    if (name != "") {
      return name;
    }
  } catch (e) {
    console.log("[smb] Error getting domain controller name", e);
  }

  return "";
}

function getDomainControllerNameBySMB(host) {
  const s = require("nuclei/libsmb");
  const sc = s.Client();
  var list = sc.ListSMBv2Metadata(host, 445);
  if (!list) {
    return "";
  }
  if (list && list.DNSDomainName != "") {
    console.log("[smb] Got domain controller", list.DNSDomainName);
    return list.DNSDomainName;
  }
}

function getDomainControllerNameByLDAP(host) {
  const l = require("nuclei/libldap");
  const lc = l.Client();
  var list = lc.CollectLdapMetadata("", host);
  if (!list) {
    return "";
  }
  if (list && list.domain != "") {
    console.log("[ldap] Got domain controller", list.domain);
    return list.domain;
  }
}
