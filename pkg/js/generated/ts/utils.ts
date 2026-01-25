

/**
 * Utils is a struct for utils functions
 * @example
 * ```javascript
 * const utils = require('nuclei/utils');
 * ```
 */
export class Utils {
    

    // Constructor of Utils
    constructor() {}
    /**
    * PatternCreate creates a cyclic pattern of specified length for buffer overflow analysis
    * The pattern is designed to have unique 4-byte sequences for easy offset identification
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const pattern = utils.PatternCreate(1000);
    * ```
    */
    public PatternCreate(length: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PatternOffset finds the offset of a 4-byte pattern within a cyclic pattern
    * Returns -1 if pattern is not found
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const pattern = utils.PatternCreate(1000);
    * const offset = utils.PatternOffset(pattern, ToBytes('Aa0A'));
    * ```
    */
    public PatternOffset(pattern: Uint8Array): number {
        return 0;
    }
    

    /**
    * FindBytes finds the first occurrence of needle in haystack
    * Returns -1 if not found
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const idx = utils.FindBytes([0x41, 0x42, 0x43, 0x44], [0x42, 0x43]);
    * ```
    */
    public FindBytes(haystack: Uint8Array): number {
        return 0;
    }
    

    /**
    * FindAllBytes finds all occurrences of needle in haystack
    * Returns array of indices
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const indices = utils.FindAllBytes([0x41, 0x42, 0x41, 0x42], [0x41, 0x42]);
    * ```
    */
    public FindAllBytes(haystack: Uint8Array): number[] {
        return [];
    }
    

    /**
    * ReplaceBytes replaces all occurrences of old with new in data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const result = utils.ReplaceBytes([0x41, 0x42, 0x43], [0x42], [0x44, 0x45]);
    * ```
    */
    public ReplaceBytes(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * RepeatBytes repeats data count times
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const repeated = utils.RepeatBytes([0x41, 0x42], 3);
    * ```
    */
    public RepeatBytes(data: Uint8Array, count: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * ReverseBytes reverses a byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const reversed = utils.ReverseBytes([0x41, 0x42, 0x43]);
    * ```
    */
    public ReverseBytes(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * SwapEndian16 swaps endianness of 16-bit values in data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const swapped = utils.SwapEndian16([0x01, 0x02, 0x03, 0x04]);
    * ```
    */
    public SwapEndian16(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * SwapEndian32 swaps endianness of 32-bit values in data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const swapped = utils.SwapEndian32([0x01, 0x02, 0x03, 0x04]);
    * ```
    */
    public SwapEndian32(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * GenerateRandomString generates a random string of specified length
    * using alphanumeric characters
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const str = utils.GenerateRandomString(16);
    * ```
    */
    public GenerateRandomString(length: number): string {
        return "";
    }
    

    /**
    * GenerateRandomAlphanumeric generates a random alphanumeric string
    * (alias for GenerateRandomString)
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const str = utils.GenerateRandomAlphanumeric(16);
    * ```
    */
    public GenerateRandomAlphanumeric(length: number): string {
        return "";
    }
    

    /**
    * GenerateRandomBytes generates random bytes of specified length
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const bytes = utils.GenerateRandomBytes(16);
    * ```
    */
    public GenerateRandomBytes(length: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * RepeatString repeats a string count times
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const repeated = utils.RepeatString('A', 100);
    * ```
    */
    public RepeatString(s: string, count: number): string {
        return "";
    }
    

    /**
    * PadLeft pads string on the left to specified length
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const padded = utils.PadLeft('123', 8, '0');
    * ```
    */
    public PadLeft(s: string, length: number, pad: string): string {
        return "";
    }
    

    /**
    * PadRight pads string on the right to specified length
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const padded = utils.PadRight('123', 8, '0');
    * ```
    */
    public PadRight(s: string, length: number, pad: string): string {
        return "";
    }
    

    /**
    * ZlibCompress compresses data using zlib
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const compressed = utils.ZlibCompress('hello world');
    * ```
    */
    public ZlibCompress(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * ZlibDecompress decompresses zlib compressed data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decompressed = utils.ZlibDecompress(compressed);
    * ```
    */
    public ZlibDecompress(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * GzipCompress compresses data using gzip
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const compressed = utils.GzipCompress('hello world');
    * ```
    */
    public GzipCompress(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * GzipDecompress decompresses gzip compressed data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decompressed = utils.GzipDecompress(compressed);
    * ```
    */
    public GzipDecompress(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * DeflateCompress compresses data using raw deflate (no zlib header)
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const compressed = utils.DeflateCompress('hello world');
    * ```
    */
    public DeflateCompress(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * DeflateDecompress decompresses raw deflate compressed data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decompressed = utils.DeflateDecompress(compressed);
    * ```
    */
    public DeflateDecompress(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * AESEncryptECB encrypts data using AES in ECB mode
    * Key must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const key = Rand(16);
    * const encrypted = utils.AESEncryptECB(ToBytes('plaintext'), key);
    * ```
    */
    public AESEncryptECB(plaintext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * AESDecryptECB decrypts data using AES in ECB mode
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decrypted = utils.AESDecryptECB(encrypted, key);
    * ```
    */
    public AESDecryptECB(ciphertext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * AESEncryptCBC encrypts data using AES in CBC mode
    * Key must be 16, 24, or 32 bytes. IV must be 16 bytes.
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const key = Rand(16);
    * const iv = Rand(16);
    * const encrypted = utils.AESEncryptCBC(ToBytes('plaintext'), key, iv);
    * ```
    */
    public AESEncryptCBC(plaintext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * AESDecryptCBC decrypts data using AES in CBC mode
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decrypted = utils.AESDecryptCBC(encrypted, key, iv);
    * ```
    */
    public AESDecryptCBC(ciphertext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * AESEncryptGCM encrypts data using AES in GCM mode
    * Key must be 16, 24, or 32 bytes. Nonce should be 12 bytes.
    * Returns ciphertext with authentication tag appended.
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const key = Rand(16);
    * const nonce = Rand(12);
    * const encrypted = utils.AESEncryptGCM(ToBytes('plaintext'), key, nonce);
    * ```
    */
    public AESEncryptGCM(plaintext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * AESDecryptGCM decrypts data using AES in GCM mode
    * Expects ciphertext with authentication tag appended.
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decrypted = utils.AESDecryptGCM(encrypted, key, nonce);
    * ```
    */
    public AESDecryptGCM(ciphertext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * DESEncryptECB encrypts data using DES in ECB mode
    * Key must be 8 bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const key = Rand(8);
    * const encrypted = utils.DESEncryptECB(ToBytes('plaintext'), key);
    * ```
    */
    public DESEncryptECB(plaintext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * DESDecryptECB decrypts data using DES in ECB mode
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decrypted = utils.DESDecryptECB(encrypted, key);
    * ```
    */
    public DESDecryptECB(ciphertext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * DES3EncryptCBC encrypts data using Triple DES in CBC mode
    * Key must be 24 bytes. IV must be 8 bytes.
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const key = Rand(24);
    * const iv = Rand(8);
    * const encrypted = utils.DES3EncryptCBC(ToBytes('plaintext'), key, iv);
    * ```
    */
    public DES3EncryptCBC(plaintext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * DES3DecryptCBC decrypts data using Triple DES in CBC mode
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decrypted = utils.DES3DecryptCBC(encrypted, key, iv);
    * ```
    */
    public DES3DecryptCBC(ciphertext: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * RC4Encrypt encrypts/decrypts data using RC4 (symmetric)
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const key = Rand(16);
    * const encrypted = utils.RC4Encrypt(ToBytes('plaintext'), key);
    * const decrypted = utils.RC4Encrypt(encrypted, key); // RC4 is symmetric
    * ```
    */
    public RC4Encrypt(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * XORBytes XORs data with a repeating key
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const xored = utils.XORBytes([0x41, 0x42, 0x43], [0x01, 0x02]);
    * ```
    */
    public XORBytes(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * XORSingleByte XORs each byte of data with a single byte key
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const xored = utils.XORSingleByte([0x41, 0x42, 0x43], 0x01);
    * ```
    */
    public XORSingleByte(data: Uint8Array, key: byte): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * URLEncode URL encodes a string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.URLEncode('hello world');
    * ```
    */
    public URLEncode(data: string): string {
        return "";
    }
    

    /**
    * URLDecode URL decodes a string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decoded = utils.URLDecode('hello%20world');
    * ```
    */
    public URLDecode(data: string): string | null {
        return null;
    }
    

    /**
    * HTMLEncode HTML encodes a string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.HTMLEncode('<script>alert(1)</script>');
    * ```
    */
    public HTMLEncode(data: string): string {
        return "";
    }
    

    /**
    * HTMLDecode HTML decodes a string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decoded = utils.HTMLDecode('&lt;script&gt;');
    * ```
    */
    public HTMLDecode(data: string): string {
        return "";
    }
    

    /**
    * HexEncode encodes bytes to hex string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hex = utils.HexEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    * ```
    */
    public HexEncode(data: Uint8Array): string {
        return "";
    }
    

    /**
    * HexDecode decodes hex string to bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const bytes = utils.HexDecode('48656c6c6f');
    * ```
    */
    public HexDecode(data: string): Uint8Array | null {
        return null;
    }
    

    /**
    * Base64Encode encodes bytes to base64 string (standard encoding)
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.Base64Encode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    * ```
    */
    public Base64Encode(data: Uint8Array): string {
        return "";
    }
    

    /**
    * Base64Decode decodes base64 string to bytes (standard encoding)
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const bytes = utils.Base64Decode('SGVsbG8=');
    * ```
    */
    public Base64Decode(data: string): Uint8Array | null {
        return null;
    }
    

    /**
    * Base64URLEncode encodes bytes to URL-safe base64 string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.Base64URLEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    * ```
    */
    public Base64URLEncode(data: Uint8Array): string {
        return "";
    }
    

    /**
    * Base64URLDecode decodes URL-safe base64 string to bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const bytes = utils.Base64URLDecode('SGVsbG8');
    * ```
    */
    public Base64URLDecode(data: string): Uint8Array | null {
        return null;
    }
    

    /**
    * Base64RawEncode encodes bytes to base64 string without padding
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.Base64RawEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    * ```
    */
    public Base64RawEncode(data: Uint8Array): string {
        return "";
    }
    

    /**
    * Base64RawDecode decodes base64 string without padding to bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const bytes = utils.Base64RawDecode('SGVsbG8');
    * ```
    */
    public Base64RawDecode(data: string): Uint8Array | null {
        return null;
    }
    

    /**
    * Base64RawURLEncode encodes bytes to URL-safe base64 string without padding
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.Base64RawURLEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    * ```
    */
    public Base64RawURLEncode(data: Uint8Array): string {
        return "";
    }
    

    /**
    * Base64RawURLDecode decodes URL-safe base64 string without padding to bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const bytes = utils.Base64RawURLDecode('SGVsbG8');
    * ```
    */
    public Base64RawURLDecode(data: string): Uint8Array | null {
        return null;
    }
    

    /**
    * UTF16LEEncode encodes a string to UTF-16 Little Endian bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.UTF16LEEncode('hello');
    * ```
    */
    public UTF16LEEncode(data: string): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * UTF16LEDecode decodes UTF-16 Little Endian bytes to a string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decoded = utils.UTF16LEDecode([0x68, 0x00, 0x65, 0x00]);
    * ```
    */
    public UTF16LEDecode(data: Uint8Array): string {
        return "";
    }
    

    /**
    * UTF16BEEncode encodes a string to UTF-16 Big Endian bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const encoded = utils.UTF16BEEncode('hello');
    * ```
    */
    public UTF16BEEncode(data: string): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * UTF16BEDecode decodes UTF-16 Big Endian bytes to a string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const decoded = utils.UTF16BEDecode([0x00, 0x68, 0x00, 0x65]);
    * ```
    */
    public UTF16BEDecode(data: Uint8Array): string {
        return "";
    }
    

    /**
    * MD4 computes MD4 hash of data (needed for NTLM)
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.MD4('password');
    * ```
    */
    public MD4(data: Uint8Array): string {
        return "";
    }
    

    /**
    * MD4Raw computes MD4 hash of data and returns raw bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.MD4Raw('password');
    * ```
    */
    public MD4Raw(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * MD5 computes MD5 hash of data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.MD5('password');
    * ```
    */
    public MD5(data: Uint8Array): string {
        return "";
    }
    

    /**
    * MD5Raw computes MD5 hash of data and returns raw bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.MD5Raw('password');
    * ```
    */
    public MD5Raw(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * SHA1 computes SHA1 hash of data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA1('password');
    * ```
    */
    public SHA1(data: Uint8Array): string {
        return "";
    }
    

    /**
    * SHA1Raw computes SHA1 hash of data and returns raw bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA1Raw('password');
    * ```
    */
    public SHA1Raw(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * SHA256 computes SHA256 hash of data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA256('password');
    * ```
    */
    public SHA256(data: Uint8Array): string {
        return "";
    }
    

    /**
    * SHA256Raw computes SHA256 hash of data and returns raw bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA256Raw('password');
    * ```
    */
    public SHA256Raw(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * SHA384 computes SHA384 hash of data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA384('password');
    * ```
    */
    public SHA384(data: Uint8Array): string {
        return "";
    }
    

    /**
    * SHA384Raw computes SHA384 hash of data and returns raw bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA384Raw('password');
    * ```
    */
    public SHA384Raw(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * SHA512 computes SHA512 hash of data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA512('password');
    * ```
    */
    public SHA512(data: Uint8Array): string {
        return "";
    }
    

    /**
    * SHA512Raw computes SHA512 hash of data and returns raw bytes
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hash = utils.SHA512Raw('password');
    * ```
    */
    public SHA512Raw(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * HMACMD5 computes HMAC-MD5 of data with key
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hmac = utils.HMACMD5('message', 'key');
    * ```
    */
    public HMACMD5(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * HMACSHA1 computes HMAC-SHA1 of data with key
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hmac = utils.HMACSHA1('message', 'key');
    * ```
    */
    public HMACSHA1(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * HMACSHA256 computes HMAC-SHA256 of data with key
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hmac = utils.HMACSHA256('message', 'key');
    * ```
    */
    public HMACSHA256(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * HMACSHA512 computes HMAC-SHA512 of data with key
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const hmac = utils.HMACSHA512('message', 'key');
    * ```
    */
    public HMACSHA512(data: Uint8Array): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * CRC32 computes CRC32 checksum of data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const checksum = utils.CRC32('data');
    * ```
    */
    public CRC32(data: Uint8Array): number {
        return 0;
    }
    

    /**
    * Adler32 computes Adler32 checksum of data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const checksum = utils.Adler32('data');
    * ```
    */
    public Adler32(data: Uint8Array): number {
        return 0;
    }
    

    /**
    * PKCS7Pad pads data to the specified block size using PKCS7 padding
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const padded = utils.PKCS7Pad([0x41, 0x42, 0x43], 16);
    * ```
    */
    public PKCS7Pad(data: Uint8Array, blockSize: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PKCS7Unpad removes PKCS7 padding from data
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const unpadded = utils.PKCS7Unpad(padded);
    * ```
    */
    public PKCS7Unpad(data: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * ZeroPad pads data with zeros to the specified length
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const padded = utils.ZeroPad([0x41, 0x42], 8);
    * ```
    */
    public ZeroPad(data: Uint8Array, length: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * NullPad pads data with null bytes to the specified length
    * (same as ZeroPad, provided for clarity)
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const padded = utils.NullPad([0x41, 0x42], 8);
    * ```
    */
    public NullPad(data: Uint8Array, length: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PadToBlockSize pads data to be a multiple of blockSize using zero padding
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const padded = utils.PadToBlockSize([0x41, 0x42, 0x43], 8);
    * ```
    */
    public PadToBlockSize(data: Uint8Array, blockSize: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PackUint8 packs a uint8 value into a byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const packed = u.PackUint8(255);
    * ```
    */
    public PackUint8(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PackUint16LE packs a uint16 value into a little-endian byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const packed = u.PackUint16LE(0x1234); // returns [0x34, 0x12]
    * ```
    */
    public PackUint16LE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PackUint16BE packs a uint16 value into a big-endian byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const packed = u.PackUint16BE(0x1234); // returns [0x12, 0x34]
    * ```
    */
    public PackUint16BE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PackUint32LE packs a uint32 value into a little-endian byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const packed = u.PackUint32LE(0x12345678); // returns [0x78, 0x56, 0x34, 0x12]
    * ```
    */
    public PackUint32LE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PackUint32BE packs a uint32 value into a big-endian byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const packed = u.PackUint32BE(0x12345678); // returns [0x12, 0x34, 0x56, 0x78]
    * ```
    */
    public PackUint32BE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PackUint64LE packs a uint64 value into a little-endian byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const packed = u.PackUint64LE(0x123456789ABCDEF0);
    * ```
    */
    public PackUint64LE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * PackUint64BE packs a uint64 value into a big-endian byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const packed = u.PackUint64BE(0x123456789ABCDEF0);
    * ```
    */
    public PackUint64BE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * UnpackUint16LE unpacks a little-endian uint16 from bytes at the given offset
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const value = u.UnpackUint16LE([0x34, 0x12, 0x00, 0x00], 0); // returns 0x1234
    * ```
    */
    public UnpackUint16LE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * UnpackUint16BE unpacks a big-endian uint16 from bytes at the given offset
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const value = u.UnpackUint16BE([0x12, 0x34, 0x00, 0x00], 0); // returns 0x1234
    * ```
    */
    public UnpackUint16BE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * UnpackUint32LE unpacks a little-endian uint32 from bytes at the given offset
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const value = u.UnpackUint32LE([0x78, 0x56, 0x34, 0x12], 0); // returns 0x12345678
    * ```
    */
    public UnpackUint32LE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * UnpackUint32BE unpacks a big-endian uint32 from bytes at the given offset
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const value = u.UnpackUint32BE([0x12, 0x34, 0x56, 0x78], 0); // returns 0x12345678
    * ```
    */
    public UnpackUint32BE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * UnpackUint64LE unpacks a little-endian uint64 from bytes at the given offset
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const value = u.UnpackUint64LE(bytes, 0);
    * ```
    */
    public UnpackUint64LE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * UnpackUint64BE unpacks a big-endian uint64 from bytes at the given offset
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const value = u.UnpackUint64BE(bytes, 0);
    * ```
    */
    public UnpackUint64BE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * ConcatBytes concatenates multiple byte slices into one
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const result = u.ConcatBytes([0x01, 0x02], [0x03, 0x04], [0x05]);
    * ```
    */
    public ConcatBytes(arrays: any): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * StringToBytes converts a string to a byte slice
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const bytes = u.StringToBytes('hello');
    * ```
    */
    public StringToBytes(s: string): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * BytesToString converts a byte slice to a string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const str = u.BytesToString([0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    * ```
    */
    public BytesToString(data: Uint8Array): string {
        return "";
    }
    

    /**
    * ToBytes converts various input types to a byte slice
    * Handles: []byte, []interface{} (with numeric values), string
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const bytes = u.ToBytes([0x41, 0x42, 0x43]);
    * ```
    */
    public ToBytes(data: any): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * P8 packs a uint8 value (pwntools-style alias for PackUint8)
    */
    public P8(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * P16 packs a uint16 value as little-endian (pwntools-style alias)
    */
    public P16(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * P16BE packs a uint16 value as big-endian
    */
    public P16BE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * P32 packs a uint32 value as little-endian (pwntools-style alias)
    */
    public P32(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * P32BE packs a uint32 value as big-endian
    */
    public P32BE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * P64 packs a uint64 value as little-endian (pwntools-style alias)
    */
    public P64(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * P64BE packs a uint64 value as big-endian
    */
    public P64BE(value: number): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * U16 unpacks a little-endian uint16 (pwntools-style alias)
    */
    public U16(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * U16BE unpacks a big-endian uint16
    */
    public U16BE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * U32 unpacks a little-endian uint32 (pwntools-style alias)
    */
    public U32(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * U32BE unpacks a big-endian uint32
    */
    public U32BE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * U64 unpacks a little-endian uint64 (pwntools-style alias)
    */
    public U64(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * U64BE unpacks a big-endian uint64
    */
    public U64BE(data: Uint8Array, offset: number): number {
        return 0;
    }
    

    /**
    * Flat combines multiple items into a single byte slice
    * Accepts: []byte, string, int (single byte), []interface{}, or any Pack result
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const u = new utils.Utils();
    * const payload = u.Flat(u.P32(0x41414141), "AAAA", [0x00, 0x01], 0x42);
    * ```
    */
    public Flat(items: any): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * Sleep pauses execution for the specified number of milliseconds
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * utils.Sleep(1000); // sleep for 1 second
    * ```
    */
    public Sleep(milliseconds: number): void {
        return;
    }
    

    /**
    * UnixTimestamp returns the current Unix timestamp in seconds
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const ts = utils.UnixTimestamp();
    * ```
    */
    public UnixTimestamp(): number {
        return 0;
    }
    

    /**
    * UnixTimestampMilli returns the current Unix timestamp in milliseconds
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const ts = utils.UnixTimestampMilli();
    * ```
    */
    public UnixTimestampMilli(): number {
        return 0;
    }
    

    /**
    * UnixTimestampNano returns the current Unix timestamp in nanoseconds
    * @example
    * ```javascript
    * const utils = require('nuclei/utils');
    * const ts = utils.UnixTimestampNano();
    * ```
    */
    public UnixTimestampNano(): number {
        return 0;
    }
    

}

