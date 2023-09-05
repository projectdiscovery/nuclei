/**
 * @module goconsole
 * @description goconsole implements bindings for goconsole protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class GoConsolePrinter
 * @description GoConsolePrinter is a console printer for nuclei using gologger
 */
class GoConsolePrinter {
    /**
     * @method Error
     * @description This method is not returning anything, hence removed.
     * @param {string} msg - The message to be logged.
     * @throws {Error} If an error occurred.
     * @example
     * let printer = new GoConsolePrinter();
     * printer.Error("This is an error message");
     */

    /**
     * @method Log
     * @description Logs the given message
     * @param {string} msg - The message to be logged.
     * @example
     * let printer = new GoConsolePrinter();
     * printer.Log("This is a log message");
     */
    Log(msg) {
        return;
    };

    /**
     * @method Warn
     * @description Logs the given warning message
     * @param {string} msg - The message to be logged.
     * @example
     * let printer = new GoConsolePrinter();
     * printer.Warn("This is a warning message");
     */
    Warn(msg) {
        return;
    };
};

/**
 * @function NewGoConsolePrinter
 * @description Creates a new instance of GoConsolePrinter
 * @returns {GoConsolePrinter} A new instance of GoConsolePrinter.
 * @example
 * let printer = NewGoConsolePrinter();
 */
function NewGoConsolePrinter() {
    return new GoConsolePrinter();
};


module.exports = {
    GoConsolePrinter: GoConsolePrinter,
    NewGoConsolePrinter: NewGoConsolePrinter,
};