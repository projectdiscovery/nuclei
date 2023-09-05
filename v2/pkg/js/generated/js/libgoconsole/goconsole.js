// libgoconsole implements bindings for goconsole protocol in javascript
// to be used from nuclei scanner.

// GoConsolePrinter is a console printer for nuclei using gologger
class GoConsolePrinter {
    // 
    Error(msg) {
        return;
    };
    // 
    Log(msg) {
        return;
    };
    // 
    Warn(msg) {
        return;
    };
};

function NewGoConsolePrinter() {

};


module.exports = {
    GoConsolePrinter: GoConsolePrinter,
    NewGoConsolePrinter: NewGoConsolePrinter,
};