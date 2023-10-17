/** @module fs */

/**
 * @function
 * @description ListDir lists all files and directories within a path depending on the itemType provided. itemType can be any one of ['file','dir','all']
 * @param {string} path - The path to list files and directories from.
 * @param {string} itemType - The type of items to list. Can be 'file', 'dir', or 'all'.
 * @returns {string[]} - The list of files and directories.
 * @throws {error} - The error encountered during listing.
 * @example
 * let m = require('nuclei/fs'); 
 * let items = m.ListDir('/tmp', 'all');
 */
function ListDir(path, itemType) {
    // implemented in go
};

/**
 * @function
 * @description ReadFile reads file contents within permitted paths
 * @param {string} path - The path to the file to read.
 * @returns {Uint8Array} - The contents of the file.
 * @throws {error} - The error encountered during reading.
 * @example
 * let m = require('nuclei/fs'); 
 * let content = m.ReadFile('/tmp/myfile.txt');
 */
function ReadFile(path) {
    // implemented in go
};

/**
 * @function
 * @description ReadFileAsString reads file contents within permitted paths and returns content as string
 * @param {string} path - The path to the file to read.
 * @returns {string} - The contents of the file as a string.
 * @throws {error} - The error encountered during reading.
 * @example
 * let m = require('nuclei/fs'); 
 * let content = m.ReadFileAsString('/tmp/myfile.txt');
 */
function ReadFileAsString(path) {
    // implemented in go
};

/**
 * @function
 * @description ReadFilesFromDir reads all files from a directory and returns a array with file contents of all files
 * @param {string} dir - The directory to read files from.
 * @returns {string[]} - The contents of all files in the directory.
 * @throws {error} - The error encountered during reading.
 * @example
 * let m = require('nuclei/fs'); 
 * let contentArray = m.ReadFilesFromDir('/tmp');
 */
function ReadFilesFromDir(dir) {
    // implemented in go
};

module.exports = {
    ListDir: ListDir,
    ReadFile: ReadFile,
    ReadFileAsString: ReadFileAsString,
    ReadFilesFromDir: ReadFilesFromDir,
};