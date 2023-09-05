/**
 * libgoconsole implements bindings for goconsole protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * GoConsolePrinter is a console printer for nuclei using gologger.
 */
class GoConsolePrinter {
    /**
     * Logs an error message.
     * @param {string} msg - The message to log.
     */
    Error(msg) {
        return;
    };

    /**
     * Logs a message.
     * @param {string} msg - The message to log.
     */
    Log(msg) {
        return;
    };

    /**
     * Logs a warning message.
     * @param {string} msg - The message to log.
     */
    Warn(msg) {
        return;
    };
};

/**
 * Factory function for creating a new GoConsolePrinter.
 * @returns {GoConsolePrinter} A new GoConsolePrinter instance.
 */
function NewGoConsolePrinter() {
    return new GoConsolePrinter();
};

module.exports = {
    GoConsolePrinter: GoConsolePrinter,
    NewGoConsolePrinter: NewGoConsolePrinter,
};