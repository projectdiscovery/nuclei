// dump_json dumps the data as JSON to the console.
// It returns beautified JSON.
function dump_json(data) {
  console.log(JSON.stringify(data, null, 2));
}

// to_json returns beautified JSON.
function to_json(data) {
  return JSON.stringify(data, null, 2);
}

// to_array sets object type as array
function to_array(data) {
  return Object.setPrototypeOf(data, Array.prototype);
}

// hex_to_ascii converts a hex string to ascii.
function hex_to_ascii(str1) {
  var hex = str1.toString();
  var str = "";
  for (var n = 0; n < hex.length; n += 2) {
    str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
  }
  return str;
}
