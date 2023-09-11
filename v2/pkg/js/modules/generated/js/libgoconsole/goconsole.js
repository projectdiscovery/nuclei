/**
 * @module goconsole
 */

/**
 * @class
 * GoConsolePrinter is a console printer for nuclei using gologger
 */
class GoConsolePrinter {
    /**
     * @method
     * @param {string} msg - The message to be printed
     * @throws {Error} If an error occurred
     * @example
     * let printer = new GoConsolePrinter();
     * printer.Error("This is an error message");
     */
    Error(msg) {
        // implemented in go
    };

    /**
     * @method
     * @param {string} msg - The message to be logged
     * @example
     * let printer = new GoConsolePrinter();
     * printer.Log("This is a log message");
     */
    Log(msg) {
        // implemented in go
    };

    /**
     * @method
     * @param {string} msg - The message to be warned
     * @example
     * let printer = new GoConsolePrinter();
     * printer.Warn("This is a warning message");
     */
    Warn(msg) {
        // implemented in go
    };
};

/**
 * @function
 * @returns {GoConsolePrinter} A new instance of GoConsolePrinter
 * @example
 * let printer = NewGoConsolePrinter();
 */
function NewGoConsolePrinter() {
    // implemented in go
};

// ReadOnly DONOT EDIT
module.exports = {
    GoConsolePrinter: GoConsolePrinter,
    NewGoConsolePrinter: NewGoConsolePrinter,
};