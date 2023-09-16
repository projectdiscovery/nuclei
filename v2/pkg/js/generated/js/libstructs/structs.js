/** 
 * @module structs 
 */

/**
 * @class
 * @name Pack
 * @param {string} formatStr - The format string.
 * @param {Object} msg - The message object.
 * @method
 * @example
 * let data = structs.pack("H", 0)
 */
function Pack(formatStr, msg) {
    // implemented in go
};

/**
 * @function
 * @name StructsCalcSize
 * @param {string} format - The format string.
 * @returns {number} The calculated size.
 * @example
 * let size = StructsCalcSize('formatString');
 */
function StructsCalcSize(format) {
    // implemented in go
};

/**
 * @class
 * @name Unpack
 * @param {string} format - The format string.
 * @param {Object} msg - The message object.
 * @method
 * @example
 * let data = structs.Unpack(">I", buff[:nb])
 */
function Unpack(format, msg) {
    // implemented in go
};

module.exports = {
    Pack: Pack,
    StructsCalcSize: StructsCalcSize,
    Unpack: Unpack,
};