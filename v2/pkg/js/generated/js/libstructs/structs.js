/**@module structs */

/**
 * @function
 * @description Pack returns a byte slice containing the values of msg slice packed according to the given format.
 * The items of msg slice must match the values required by the format exactly.
 * @param {string} formatStr - The format string.
 * @param {any[]} msg - The message to be packed.
 * @returns {Uint8Array} - The packed message in a byte array.
 * @throws {error} - The error encountered during packing.
 * @example
 * let s = require('nuclei/structs'); 
 * let packedMsg = s.Pack("H", [0]);
 */
function Pack(formatStr, msg) {
    // implemented in go
};

/**
 * @function
 * @description StructsCalcSize returns the number of bytes needed to pack the values according to the given format.
 * @param {string} format - The format string.
 * @returns {number} - The number of bytes needed to pack the values.
 * @throws {error} - The error encountered during calculation.
 * @example
 * let s = require('nuclei/structs'); 
 * let size = s.StructsCalcSize("H");
 */
function StructsCalcSize(format) {
    // implemented in go
};

/**
 * @function
 * @description Unpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
 * The result is a []interface{} slice even if it contains exactly one item.
 * The byte slice must contain not less the amount of data required by the format
 * (len(msg) must more or equal CalcSize(format)).
 * @param {string} format - The format string.
 * @param {Uint8Array} msg - The packed message to be unpacked.
 * @throws {error} - The error encountered during unpacking.
 * @example
 * let s = require('nuclei/structs'); 
 * let unpackedMsg = s.Unpack(">I", buff[:nb]);
 */
function Unpack(format, msg) {
    // implemented in go
};

module.exports = {
    Pack: Pack,
    StructsCalcSize: StructsCalcSize,
    Unpack: Unpack,
};