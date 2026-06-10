

/**
 * ListDir lists itemType values within a directory
 * depending on the itemType provided
 * itemType can be any one of ['file','dir',”]
 * @example
 * ```javascript
 * const fs = require('nuclei/fs');
 * // this will only return files in /tmp directory
 * const files = fs.ListDir('/tmp', 'file');
 * ```
 * @example
 * ```javascript
 * const fs = require('nuclei/fs');
 * // this will only return directories in /tmp directory
 * const dirs = fs.ListDir('/tmp', 'dir');
 * ```
 * @example
 * ```javascript
 * const fs = require('nuclei/fs');
 * // when no itemType is provided, it will return both files and directories
 * const items = fs.ListDir('/tmp');
 * ```
 */
export function ListDir(path: string, itemType: string): string[] | null {
    return null;
}



/**
 * ReadFile reads file contents within permitted paths
 * and returns content as byte array
 * @example
 * ```javascript
 * const fs = require('nuclei/fs');
 * // here permitted directories are $HOME/nuclei-templates/*
 * const content = fs.ReadFile('helpers/usernames.txt');
 * ```
 */
export function ReadFile(path: string): Uint8Array | null {
    return null;
}



/**
 * ReadFileAsString reads file contents within permitted paths
 * and returns content as string
 * @example
 * ```javascript
 * const fs = require('nuclei/fs');
 * // here permitted directories are $HOME/nuclei-templates/*
 * const content = fs.ReadFileAsString('helpers/usernames.txt');
 * ```
 */
export function ReadFileAsString(path: string): string | null {
    return null;
}



/**
 * ReadFilesFromDir reads all files from a directory
 * and returns a string array with file contents of all files
 * @example
 * ```javascript
 * const fs = require('nuclei/fs');
 * // here permitted directories are $HOME/nuclei-templates/*
 * const contents = fs.ReadFilesFromDir('helpers/ssh-keys');
 * log(contents);
 * ```
 */
export function ReadFilesFromDir(dir: string): string[] | null {
    return null;
}

