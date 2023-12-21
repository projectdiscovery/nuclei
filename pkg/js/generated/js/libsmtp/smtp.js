/** @module smtp */

/**
 * @class
 * @classdesc SMTPClient is a minimal SMTP client for nuclei scripts.
 */
class SMTPClient {
    /**
    @method
    @description IsOpenRelay checks if a host is an open relay
    @param {string} host - The host to check.
    @param {number} port - The port to check.
    @param {string} msg - The message to send.
    @returns {boolean} - Whether the host is an open relay or not.
    @throws {error} - The error encountered during the check.
    @example
    let m = require('nuclei/smtp');
    let c = m.SMTPClient();
    let isOpenRelay = c.IsOpenRelay('localhost', 25, 'test message');
    */
    IsOpenRelay(host, port, msg) {
        // implemented in go
    };

    /**
    @method
    @description IsSMTP checks if a host is running a SMTP server.
    @param {string} host - The host to check.
    @param {number} port - The port to check.
    @returns {IsSMTPResponse} - The response from the SMTP server.
    @throws {error} - The error encountered during the check.
    @example
    let m = require('nuclei/smtp');
    let c = m.SMTPClient();
    let isSMTP = c.IsSMTP('localhost', 25);
    */
    IsSMTP(host, port) {
        // implemented in go
    };

    /**
    @method
    @description SendMail sends an email using the SMTP protocol.
    @param {string} host - The host to send the email to.
    @param {number} port - The port to send the email to.
    @param {string} msg - The message to send.
    @returns {boolean} - Whether the email was sent successfully or not.
    @throws {error} - The error encountered during the email sending.
    @example
    let m = require('nuclei/smtp');
    let c = m.SMTPClient();
    let isSent = c.SendMail('localhost', 25, 'test message');
    */
    SendMail(host, port, msg) {
        // implemented in go
    };
};

/**
 * @class
 * @classdesc SMTPMessage is a simple smtp message builder
 */
class SMTPMessage {
    /**
    @method
    @description Auth when called authenticates using username and password before sending the message
    @param {string} username - The username for authentication.
    @param {string} password - The password for authentication.
    @returns {SMTPMessage} - The SMTPMessage object after authentication.
    @example
    let m = require('nuclei/smtp');
    let msg = m.SMTPMessage();
    msg = msg.Auth('username', 'password');
    */
    Auth(username, password) {
        // implemented in go
    };

    /**
    @method
    @description Body adds the message body to the message
    @param {string} msg - The message body to add.
    @returns {SMTPMessage} - The SMTPMessage object after adding the body.
    @example
    let m = require('nuclei/smtp');
    let msg = m.SMTPMessage();
    msg = msg.Body('This is a test message');
    */
    Body(msg) {
        // implemented in go
    };

    /**
    @method
    @description From adds the from field to the message
    @param {string} email - The email to add to the from field.
    @returns {SMTPMessage} - The SMTPMessage object after adding the from field.
    @example
    let m = require('nuclei/smtp');
    let msg = m.SMTPMessage();
    msg = msg.From('test@example.com');
    */
    From(email) {
        // implemented in go
    };

    /**
    @method
    @description String returns the string representation of the message
    @returns {string} - The string representation of the message.
    @example
    let m = require('nuclei/smtp');
    let msg = m.SMTPMessage();
    let str = msg.String();
    */
    String() {
        // implemented in go
    };

    /**
    @method
    @description Subject adds the subject field to the message
    @param {string} sub - The subject to add.
    @returns {SMTPMessage} - The SMTPMessage object after adding the subject.
    @example
    let m = require('nuclei/smtp');
    let msg = m.SMTPMessage();
    msg = msg.Subject('Test Subject');
    */
    Subject(sub) {
        // implemented in go
    };

    /**
    @method
    @description To adds the to field to the message
    @param {string} email - The email to add to the to field.
    @returns {SMTPMessage} - The SMTPMessage object after adding the to field.
    @example
    let m = require('nuclei/smtp');
    let msg = m.SMTPMessage();
    msg = msg.To('test@example.com');
    */
    To(email) {
        // implemented in go
    };
};

module.exports = {
    SMTPClient: SMTPClient,
    SMTPMessage: SMTPMessage,
};