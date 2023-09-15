/**
 * @module fs
 */

/**
 * @method
 * @name ListDir
 * @param {string} path - The path of the directory.
 * @param {string} itemType - The type of the item (values => all/file/dir)
 * @throws {Error} If an error occurred while listing the directory.
 * @example
 * // Usage of ListDir
 * let m = require('nuclei/fs');
 * let files = ListDir('helpers', 'file');
 */
function ListDir(path, itemType) {
    // implemented in go
}

/**
 * @method
 * @name ReadFile
 * @param {string} path - The path of the file.
 * @throws {Error} If an error occurred while reading the file.
 * @return {Buffer} The content of the file.
 * @example
 * // Usage of ReadFile
 * let m = require('nuclei/fs');
 * let content = ReadFile('helpers/usernames.txt');
 */
function ReadFile(path) {
    // implemented in go
}

/**
 * @method
 * @name ReadFileAsString
 * @param {string} path - The path of the file.
 * @throws {Error} If an error occurred while reading the file.
 * @return {string} The content of the file as a string.
 * @example
 * // Usage of ReadFileAsString
 * let m = require('nuclei/fs');
 * let content = ReadFileAsString('helpers/usernames.txt');
 */
function ReadFileAsString(path) {
    // implemented in go
}

module.exports = {
    ListDir: ListDir,
    ReadFile: ReadFile,
    ReadFileAsString: ReadFileAsString,
};