/** @module goconsole */

/**
 * @class
 * @classdesc GoConsolePrinter is a console printer for nuclei using gologger
 */
class GoConsolePrinter {
    /**
    * @method
    * @description Error logs an error message
    * @param {string} msg - The message to log.
    * @example
    * let m = require('nuclei/goconsole');
    * let c = m.GoConsolePrinter();
    * c.Error('This is an error message');
    */
    Error(msg) {
        // implemented in go
    };

    /**
    * @method
    * @description Log logs a message
    * @param {string} msg - The message to log.
    * @example
    * let m = require('nuclei/goconsole');
    * let c = m.GoConsolePrinter();
    * c.Log('This is a log message');
    */
    Log(msg) {
        // implemented in go
    };

    /**
    * @method
    * @description Warn logs a warning message
    * @param {string} msg - The message to log.
    * @example
    * let m = require('nuclei/goconsole');
    * let c = m.GoConsolePrinter();
    * c.Warn('This is a warning message');
    */
    Warn(msg) {
        // implemented in go
    };
};

/**
 * @function
 * @description NewGoConsolePrinter creates a new instance of GoConsolePrinter
 * @returns {GoConsolePrinter} - The new instance of GoConsolePrinter.
 * @example
 * let m = require('nuclei/goconsole'); 
 * let printer = m.NewGoConsolePrinter();
 */
function NewGoConsolePrinter() {
    // implemented in go
};

module.exports = {
    GoConsolePrinter: GoConsolePrinter,
    NewGoConsolePrinter: NewGoConsolePrinter,
};