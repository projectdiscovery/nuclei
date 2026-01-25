package utils

import (
	"bytes"
	"testing"
)

func TestURLEncode(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		input    string
		expected string
	}{
		{"hello world", "hello+world"},
		{"test@example.com", "test%40example.com"},
		{"a=b&c=d", "a%3Db%26c%3Dd"},
	}
	for _, tt := range tests {
		result := u.URLEncode(tt.input)
		if result != tt.expected {
			t.Errorf("URLEncode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestURLDecode(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		input    string
		expected string
	}{
		{"hello+world", "hello world"},
		{"test%40example.com", "test@example.com"},
		{"a%3Db%26c%3Dd", "a=b&c=d"},
	}
	for _, tt := range tests {
		result, err := u.URLDecode(tt.input)
		if err != nil {
			t.Errorf("URLDecode(%q) error: %v", tt.input, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("URLDecode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHTMLEncode(t *testing.T) {
	u := &Utils{}
	input := "<script>alert('xss')</script>"
	expected := "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
	result := u.HTMLEncode(input)
	if result != expected {
		t.Errorf("HTMLEncode(%q) = %q, want %q", input, result, expected)
	}
}

func TestHTMLDecode(t *testing.T) {
	u := &Utils{}
	input := "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
	expected := "<script>alert('xss')</script>"
	result := u.HTMLDecode(input)
	if result != expected {
		t.Errorf("HTMLDecode(%q) = %q, want %q", input, result, expected)
	}
}

func TestHexEncodeDecode(t *testing.T) {
	u := &Utils{}
	data := []byte("hello")
	encoded := u.HexEncode(data)
	if encoded != "68656c6c6f" {
		t.Errorf("HexEncode = %q, want %q", encoded, "68656c6c6f")
	}
	decoded, err := u.HexDecode(encoded)
	if err != nil {
		t.Errorf("HexDecode error: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("HexDecode = %v, want %v", decoded, data)
	}
}

func TestBase64EncodeDecode(t *testing.T) {
	u := &Utils{}
	data := []byte("hello world")
	encoded := u.Base64Encode(data)
	if encoded != "aGVsbG8gd29ybGQ=" {
		t.Errorf("Base64Encode = %q, want %q", encoded, "aGVsbG8gd29ybGQ=")
	}
	decoded, err := u.Base64Decode(encoded)
	if err != nil {
		t.Errorf("Base64Decode error: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Base64Decode = %v, want %v", decoded, data)
	}
}

func TestBase64URLEncodeDecode(t *testing.T) {
	u := &Utils{}
	data := []byte{0xfb, 0xff, 0xfe}
	encoded := u.Base64URLEncode(data)
	decoded, err := u.Base64URLDecode(encoded)
	if err != nil {
		t.Errorf("Base64URLDecode error: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Base64URL roundtrip failed")
	}
}

func TestBase64RawEncodeDecode(t *testing.T) {
	u := &Utils{}
	data := []byte("test")
	encoded := u.Base64RawEncode(data)
	if encoded != "dGVzdA" {
		t.Errorf("Base64RawEncode = %q, want %q", encoded, "dGVzdA")
	}
	decoded, err := u.Base64RawDecode(encoded)
	if err != nil {
		t.Errorf("Base64RawDecode error: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Base64RawDecode = %v, want %v", decoded, data)
	}
}

func TestUTF16LEEncodeDecode(t *testing.T) {
	u := &Utils{}
	data := "hello"
	encoded := u.UTF16LEEncode(data)
	expected := []byte{0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("UTF16LEEncode = %v, want %v", encoded, expected)
	}
	decoded := u.UTF16LEDecode(encoded)
	if decoded != data {
		t.Errorf("UTF16LEDecode = %q, want %q", decoded, data)
	}
}

func TestUTF16BEEncodeDecode(t *testing.T) {
	u := &Utils{}
	data := "hello"
	encoded := u.UTF16BEEncode(data)
	expected := []byte{0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("UTF16BEEncode = %v, want %v", encoded, expected)
	}
	decoded := u.UTF16BEDecode(encoded)
	if decoded != data {
		t.Errorf("UTF16BEDecode = %q, want %q", decoded, data)
	}
}

func TestMD5(t *testing.T) {
	u := &Utils{}
	result := u.MD5([]byte("hello"))
	expected := "5d41402abc4b2a76b9719d911017c592"
	if result != expected {
		t.Errorf("MD5 = %q, want %q", result, expected)
	}
}

func TestSHA1(t *testing.T) {
	u := &Utils{}
	result := u.SHA1([]byte("hello"))
	expected := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	if result != expected {
		t.Errorf("SHA1 = %q, want %q", result, expected)
	}
}

func TestSHA256(t *testing.T) {
	u := &Utils{}
	result := u.SHA256([]byte("hello"))
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if result != expected {
		t.Errorf("SHA256 = %q, want %q", result, expected)
	}
}

func TestSHA512(t *testing.T) {
	u := &Utils{}
	result := u.SHA512([]byte("hello"))
	expected := "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
	if result != expected {
		t.Errorf("SHA512 = %q, want %q", result, expected)
	}
}

func TestHMACSHA256(t *testing.T) {
	u := &Utils{}
	result := u.HMACSHA256([]byte("message"), []byte("key"))
	if len(result) != 32 {
		t.Errorf("HMACSHA256 length = %d, want 32", len(result))
	}
	result2 := u.HMACSHA256([]byte("message"), []byte("key"))
	if !bytes.Equal(result, result2) {
		t.Errorf("HMACSHA256 is not deterministic")
	}
	result3 := u.HMACSHA256([]byte("different"), []byte("key"))
	if bytes.Equal(result, result3) {
		t.Errorf("HMACSHA256 should produce different output for different input")
	}
}

func TestCRC32(t *testing.T) {
	u := &Utils{}
	result := u.CRC32([]byte("hello"))
	expected := uint32(0x3610a686)
	if result != expected {
		t.Errorf("CRC32 = %x, want %x", result, expected)
	}
}

func TestZlibCompressDecompress(t *testing.T) {
	u := &Utils{}
	data := []byte("hello world hello world hello world")
	compressed, err := u.ZlibCompress(data)
	if err != nil {
		t.Errorf("ZlibCompress error: %v", err)
	}
	if len(compressed) >= len(data) {
		t.Logf("Warning: compressed size (%d) >= original size (%d)", len(compressed), len(data))
	}
	decompressed, err := u.ZlibDecompress(compressed)
	if err != nil {
		t.Errorf("ZlibDecompress error: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Errorf("Zlib roundtrip failed")
	}
}

func TestGzipCompressDecompress(t *testing.T) {
	u := &Utils{}
	data := []byte("hello world hello world hello world")
	compressed, err := u.GzipCompress(data)
	if err != nil {
		t.Errorf("GzipCompress error: %v", err)
	}
	decompressed, err := u.GzipDecompress(compressed)
	if err != nil {
		t.Errorf("GzipDecompress error: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Errorf("Gzip roundtrip failed")
	}
}

func TestDeflateCompressDecompress(t *testing.T) {
	u := &Utils{}
	data := []byte("hello world hello world hello world")
	compressed, err := u.DeflateCompress(data)
	if err != nil {
		t.Errorf("DeflateCompress error: %v", err)
	}
	decompressed, err := u.DeflateDecompress(compressed)
	if err != nil {
		t.Errorf("DeflateDecompress error: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Errorf("Deflate roundtrip failed")
	}
}

func TestAESEncryptDecryptECB(t *testing.T) {
	u := &Utils{}
	key := []byte("0123456789abcdef")
	plaintext := []byte("hello world test")
	encrypted, err := u.AESEncryptECB(plaintext, key)
	if err != nil {
		t.Errorf("AESEncryptECB error: %v", err)
	}
	decrypted, err := u.AESDecryptECB(encrypted, key)
	if err != nil {
		t.Errorf("AESDecryptECB error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("AES ECB roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESEncryptDecryptCBC(t *testing.T) {
	u := &Utils{}
	key := []byte("0123456789abcdef")
	iv := []byte("abcdefghijklmnop")
	plaintext := []byte("hello world test")
	encrypted, err := u.AESEncryptCBC(plaintext, key, iv)
	if err != nil {
		t.Errorf("AESEncryptCBC error: %v", err)
	}
	decrypted, err := u.AESDecryptCBC(encrypted, key, iv)
	if err != nil {
		t.Errorf("AESDecryptCBC error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("AES CBC roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESEncryptDecryptGCM(t *testing.T) {
	u := &Utils{}
	key := []byte("0123456789abcdef")
	nonce := []byte("123456789012")
	plaintext := []byte("hello world test")
	encrypted, err := u.AESEncryptGCM(plaintext, key, nonce)
	if err != nil {
		t.Errorf("AESEncryptGCM error: %v", err)
	}
	decrypted, err := u.AESDecryptGCM(encrypted, key, nonce)
	if err != nil {
		t.Errorf("AESDecryptGCM error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("AES GCM roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestDESEncryptDecryptECB(t *testing.T) {
	u := &Utils{}
	key := []byte("12345678")
	plaintext := []byte("hello wo")
	encrypted, err := u.DESEncryptECB(plaintext, key)
	if err != nil {
		t.Errorf("DESEncryptECB error: %v", err)
	}
	decrypted, err := u.DESDecryptECB(encrypted, key)
	if err != nil {
		t.Errorf("DESDecryptECB error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DES ECB roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestDES3EncryptDecryptCBC(t *testing.T) {
	u := &Utils{}
	key := []byte("123456789012345678901234")
	iv := []byte("12345678")
	plaintext := []byte("hello world test")
	encrypted, err := u.DES3EncryptCBC(plaintext, key, iv)
	if err != nil {
		t.Errorf("DES3EncryptCBC error: %v", err)
	}
	decrypted, err := u.DES3DecryptCBC(encrypted, key, iv)
	if err != nil {
		t.Errorf("DES3DecryptCBC error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("3DES CBC roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestRC4Encrypt(t *testing.T) {
	u := &Utils{}
	key := []byte("secretkey")
	plaintext := []byte("hello world")
	encrypted, err := u.RC4Encrypt(plaintext, key)
	if err != nil {
		t.Errorf("RC4Encrypt error: %v", err)
	}
	decrypted, err := u.RC4Encrypt(encrypted, key)
	if err != nil {
		t.Errorf("RC4 decrypt error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("RC4 roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestXORBytes(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43, 0x44}
	key := []byte{0x01, 0x02}
	result := u.XORBytes(data, key)
	expected := []byte{0x40, 0x40, 0x42, 0x46}
	if !bytes.Equal(result, expected) {
		t.Errorf("XORBytes = %v, want %v", result, expected)
	}
	original := u.XORBytes(result, key)
	if !bytes.Equal(original, data) {
		t.Errorf("XORBytes roundtrip failed")
	}
}

func TestXORSingleByte(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43}
	key := byte(0x01)
	result := u.XORSingleByte(data, key)
	expected := []byte{0x40, 0x43, 0x42}
	if !bytes.Equal(result, expected) {
		t.Errorf("XORSingleByte = %v, want %v", result, expected)
	}
}

func TestPKCS7PadUnpad(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43}
	padded := u.PKCS7Pad(data, 8)
	if len(padded) != 8 {
		t.Errorf("PKCS7Pad length = %d, want 8", len(padded))
	}
	unpadded, err := u.PKCS7Unpad(padded)
	if err != nil {
		t.Errorf("PKCS7Unpad error: %v", err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Errorf("PKCS7 roundtrip failed")
	}
}

func TestZeroPad(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42}
	result := u.ZeroPad(data, 8)
	expected := []byte{0x41, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(result, expected) {
		t.Errorf("ZeroPad = %v, want %v", result, expected)
	}
}

func TestPadToBlockSize(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43}
	result := u.PadToBlockSize(data, 8)
	if len(result) != 8 {
		t.Errorf("PadToBlockSize length = %d, want 8", len(result))
	}
	if !bytes.Equal(result[:3], data) {
		t.Errorf("PadToBlockSize data mismatch")
	}
}

func TestPatternCreate(t *testing.T) {
	u := &Utils{}
	pattern := u.PatternCreate(100)
	if len(pattern) != 100 {
		t.Errorf("PatternCreate length = %d, want 100", len(pattern))
	}
	if pattern[0] != 'A' || pattern[1] != 'a' || pattern[2] != '0' {
		t.Errorf("PatternCreate start = %q, want 'Aa0'", pattern[:3])
	}
}

func TestPatternOffset(t *testing.T) {
	u := &Utils{}
	pattern := u.PatternCreate(1000)
	offset := u.PatternOffset(pattern, []byte("Ab0"))
	if offset != 30 {
		t.Errorf("PatternOffset = %d, want 30", offset)
	}
}

func TestFindBytes(t *testing.T) {
	u := &Utils{}
	haystack := []byte{0x41, 0x42, 0x43, 0x44, 0x42, 0x43}
	needle := []byte{0x42, 0x43}
	idx := u.FindBytes(haystack, needle)
	if idx != 1 {
		t.Errorf("FindBytes = %d, want 1", idx)
	}
}

func TestFindAllBytes(t *testing.T) {
	u := &Utils{}
	haystack := []byte{0x41, 0x42, 0x43, 0x44, 0x42, 0x43}
	needle := []byte{0x42, 0x43}
	indices := u.FindAllBytes(haystack, needle)
	if len(indices) != 2 || indices[0] != 1 || indices[1] != 4 {
		t.Errorf("FindAllBytes = %v, want [1, 4]", indices)
	}
}

func TestReplaceBytes(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43, 0x42}
	result := u.ReplaceBytes(data, []byte{0x42}, []byte{0x44, 0x45})
	expected := []byte{0x41, 0x44, 0x45, 0x43, 0x44, 0x45}
	if !bytes.Equal(result, expected) {
		t.Errorf("ReplaceBytes = %v, want %v", result, expected)
	}
}

func TestRepeatBytes(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42}
	result := u.RepeatBytes(data, 3)
	expected := []byte{0x41, 0x42, 0x41, 0x42, 0x41, 0x42}
	if !bytes.Equal(result, expected) {
		t.Errorf("RepeatBytes = %v, want %v", result, expected)
	}
}

func TestReverseBytes(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43}
	result := u.ReverseBytes(data)
	expected := []byte{0x43, 0x42, 0x41}
	if !bytes.Equal(result, expected) {
		t.Errorf("ReverseBytes = %v, want %v", result, expected)
	}
}

func TestSwapEndian16(t *testing.T) {
	u := &Utils{}
	data := []byte{0x01, 0x02, 0x03, 0x04}
	result := u.SwapEndian16(data)
	expected := []byte{0x02, 0x01, 0x04, 0x03}
	if !bytes.Equal(result, expected) {
		t.Errorf("SwapEndian16 = %v, want %v", result, expected)
	}
}

func TestSwapEndian32(t *testing.T) {
	u := &Utils{}
	data := []byte{0x01, 0x02, 0x03, 0x04}
	result := u.SwapEndian32(data)
	expected := []byte{0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(result, expected) {
		t.Errorf("SwapEndian32 = %v, want %v", result, expected)
	}
}

func TestGenerateRandomString(t *testing.T) {
	u := &Utils{}
	s := u.GenerateRandomString(16)
	if len(s) != 16 {
		t.Errorf("GenerateRandomString length = %d, want 16", len(s))
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	u := &Utils{}
	b := u.GenerateRandomBytes(16)
	if len(b) != 16 {
		t.Errorf("GenerateRandomBytes length = %d, want 16", len(b))
	}
}

func TestRepeatString(t *testing.T) {
	u := &Utils{}
	result := u.RepeatString("AB", 3)
	if result != "ABABAB" {
		t.Errorf("RepeatString = %q, want %q", result, "ABABAB")
	}
}

func TestPadLeft(t *testing.T) {
	u := &Utils{}
	result := u.PadLeft("123", 8, "0")
	if result != "00000123" {
		t.Errorf("PadLeft = %q, want %q", result, "00000123")
	}
}

func TestPadRight(t *testing.T) {
	u := &Utils{}
	result := u.PadRight("123", 8, "0")
	if result != "12300000" {
		t.Errorf("PadRight = %q, want %q", result, "12300000")
	}
}

func TestUnixTimestamp(t *testing.T) {
	u := &Utils{}
	ts := u.UnixTimestamp()
	if ts <= 0 {
		t.Errorf("UnixTimestamp = %d, want > 0", ts)
	}
}

func TestUnixTimestampMilli(t *testing.T) {
	u := &Utils{}
	ts := u.UnixTimestampMilli()
	if ts <= 0 {
		t.Errorf("UnixTimestampMilli = %d, want > 0", ts)
	}
}

func TestUnixTimestampNano(t *testing.T) {
	u := &Utils{}
	ts := u.UnixTimestampNano()
	if ts <= 0 {
		t.Errorf("UnixTimestampNano = %d, want > 0", ts)
	}
}

func TestMD4(t *testing.T) {
	u := &Utils{}
	result := u.MD4([]byte("hello"))
	if len(result) != 32 {
		t.Errorf("MD4 length = %d, want 32", len(result))
	}
	result2 := u.MD4([]byte("hello"))
	if result != result2 {
		t.Errorf("MD4 is not deterministic")
	}
}

func TestMD4Raw(t *testing.T) {
	u := &Utils{}
	result := u.MD4Raw([]byte("hello"))
	if len(result) != 16 {
		t.Errorf("MD4Raw length = %d, want 16", len(result))
	}
}

func TestMD5Raw(t *testing.T) {
	u := &Utils{}
	result := u.MD5Raw([]byte("hello"))
	if len(result) != 16 {
		t.Errorf("MD5Raw length = %d, want 16", len(result))
	}
	expected := u.HexEncode(result)
	if expected != "5d41402abc4b2a76b9719d911017c592" {
		t.Errorf("MD5Raw hex = %q, want %q", expected, "5d41402abc4b2a76b9719d911017c592")
	}
}

func TestSHA1Raw(t *testing.T) {
	u := &Utils{}
	result := u.SHA1Raw([]byte("hello"))
	if len(result) != 20 {
		t.Errorf("SHA1Raw length = %d, want 20", len(result))
	}
}

func TestSHA256Raw(t *testing.T) {
	u := &Utils{}
	result := u.SHA256Raw([]byte("hello"))
	if len(result) != 32 {
		t.Errorf("SHA256Raw length = %d, want 32", len(result))
	}
}

func TestSHA384(t *testing.T) {
	u := &Utils{}
	result := u.SHA384([]byte("hello"))
	if len(result) != 96 {
		t.Errorf("SHA384 length = %d, want 96", len(result))
	}
}

func TestSHA384Raw(t *testing.T) {
	u := &Utils{}
	result := u.SHA384Raw([]byte("hello"))
	if len(result) != 48 {
		t.Errorf("SHA384Raw length = %d, want 48", len(result))
	}
}

func TestSHA512Raw(t *testing.T) {
	u := &Utils{}
	result := u.SHA512Raw([]byte("hello"))
	if len(result) != 64 {
		t.Errorf("SHA512Raw length = %d, want 64", len(result))
	}
}

func TestHMACMD5(t *testing.T) {
	u := &Utils{}
	result := u.HMACMD5([]byte("message"), []byte("key"))
	if len(result) != 16 {
		t.Errorf("HMACMD5 length = %d, want 16", len(result))
	}
	result2 := u.HMACMD5([]byte("message"), []byte("key"))
	if !bytes.Equal(result, result2) {
		t.Errorf("HMACMD5 is not deterministic")
	}
}

func TestHMACSHA1(t *testing.T) {
	u := &Utils{}
	result := u.HMACSHA1([]byte("message"), []byte("key"))
	if len(result) != 20 {
		t.Errorf("HMACSHA1 length = %d, want 20", len(result))
	}
}

func TestHMACSHA512(t *testing.T) {
	u := &Utils{}
	result := u.HMACSHA512([]byte("message"), []byte("key"))
	if len(result) != 64 {
		t.Errorf("HMACSHA512 length = %d, want 64", len(result))
	}
}

func TestAdler32(t *testing.T) {
	u := &Utils{}
	result := u.Adler32([]byte("hello"))
	if result == 0 {
		t.Errorf("Adler32 = 0, want non-zero")
	}
	result2 := u.Adler32([]byte("hello"))
	if result != result2 {
		t.Errorf("Adler32 is not deterministic")
	}
}

func TestNullPad(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42}
	result := u.NullPad(data, 8)
	expected := []byte{0x41, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(result, expected) {
		t.Errorf("NullPad = %v, want %v", result, expected)
	}
}

func TestGenerateRandomAlphanumeric(t *testing.T) {
	u := &Utils{}
	s := u.GenerateRandomAlphanumeric(16)
	if len(s) != 16 {
		t.Errorf("GenerateRandomAlphanumeric length = %d, want 16", len(s))
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("GenerateRandomAlphanumeric contains invalid char: %c", c)
		}
	}
}

func TestBase64RawURLEncodeDecode(t *testing.T) {
	u := &Utils{}
	data := []byte{0xfb, 0xff, 0xfe}
	encoded := u.Base64RawURLEncode(data)
	decoded, err := u.Base64RawURLDecode(encoded)
	if err != nil {
		t.Errorf("Base64RawURLDecode error: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Base64RawURL roundtrip failed")
	}
}

func TestPatternCreateCyclicUniqueness(t *testing.T) {
	u := &Utils{}
	pattern := u.PatternCreate(20280)
	seen := make(map[string]int)
	for i := 0; i <= len(pattern)-4; i++ {
		chunk := string(pattern[i : i+4])
		if prev, exists := seen[chunk]; exists {
			t.Errorf("PatternCreate: duplicate 4-byte sequence %q at offsets %d and %d", chunk, prev, i)
			return
		}
		seen[chunk] = i
	}
}

func TestPatternOffsetMultiple(t *testing.T) {
	u := &Utils{}
	pattern := u.PatternCreate(1000)

	tests := []struct {
		search   string
		expected int
	}{
		{"Aa0A", 0},
		{"Aa1A", 3},
		{"Aa2A", 6},
		{"Ab0A", 30},
		{"Ba0B", 780},
	}

	for _, tt := range tests {
		offset := u.PatternOffset(pattern, []byte(tt.search))
		if offset != tt.expected {
			t.Errorf("PatternOffset(%q) = %d, want %d", tt.search, offset, tt.expected)
		}
	}
}

func TestPatternOffsetNotFound(t *testing.T) {
	u := &Utils{}
	pattern := u.PatternCreate(100)
	offset := u.PatternOffset(pattern, []byte("ZZZZ"))
	if offset != -1 {
		t.Errorf("PatternOffset(not found) = %d, want -1", offset)
	}
}

func TestFindBytesNotFound(t *testing.T) {
	u := &Utils{}
	haystack := []byte{0x41, 0x42, 0x43}
	needle := []byte{0x44, 0x45}
	idx := u.FindBytes(haystack, needle)
	if idx != -1 {
		t.Errorf("FindBytes(not found) = %d, want -1", idx)
	}
}

func TestFindAllBytesEmpty(t *testing.T) {
	u := &Utils{}
	haystack := []byte{0x41, 0x42, 0x43}
	needle := []byte{0x44, 0x45}
	indices := u.FindAllBytes(haystack, needle)
	if len(indices) != 0 {
		t.Errorf("FindAllBytes(not found) = %v, want []", indices)
	}
}

func TestSwapEndian16OddLength(t *testing.T) {
	u := &Utils{}
	data := []byte{0x01, 0x02, 0x03}
	result := u.SwapEndian16(data)
	expected := []byte{0x02, 0x01, 0x03}
	if !bytes.Equal(result, expected) {
		t.Errorf("SwapEndian16 odd length = %v, want %v", result, expected)
	}
}

func TestSwapEndian32ShortData(t *testing.T) {
	u := &Utils{}
	data := []byte{0x01, 0x02, 0x03}
	result := u.SwapEndian32(data)
	if !bytes.Equal(result, data) {
		t.Errorf("SwapEndian32 short data = %v, want %v (unchanged)", result, data)
	}
}

func TestXORBytesEmptyKey(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43}
	result := u.XORBytes(data, []byte{})
	if !bytes.Equal(result, data) {
		t.Errorf("XORBytes empty key = %v, want %v (unchanged)", result, data)
	}
}

func TestPKCS7UnpadInvalid(t *testing.T) {
	u := &Utils{}
	_, err := u.PKCS7Unpad([]byte{})
	if err == nil {
		t.Errorf("PKCS7Unpad empty should return error")
	}
	_, err = u.PKCS7Unpad([]byte{0x00})
	if err == nil {
		t.Errorf("PKCS7Unpad zero padding should return error")
	}
}

func TestZeroPadAlreadyLong(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43, 0x44, 0x45}
	result := u.ZeroPad(data, 3)
	if !bytes.Equal(result, data) {
		t.Errorf("ZeroPad already long = %v, want %v (unchanged)", result, data)
	}
}

func TestPadToBlockSizeAlreadyAligned(t *testing.T) {
	u := &Utils{}
	data := []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}
	result := u.PadToBlockSize(data, 8)
	if !bytes.Equal(result, data) {
		t.Errorf("PadToBlockSize already aligned = %v, want %v (unchanged)", result, data)
	}
}

func TestPackUint8(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		input    int
		expected []byte
	}{
		{0, []byte{0x00}},
		{255, []byte{0xFF}},
		{0x41, []byte{0x41}},
		{256, []byte{0x00}},
	}
	for _, tt := range tests {
		result := u.PackUint8(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("PackUint8(%d) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestPackUint16LE(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		input    int
		expected []byte
	}{
		{0x1234, []byte{0x34, 0x12}},
		{0, []byte{0x00, 0x00}},
		{0xFFFF, []byte{0xFF, 0xFF}},
		{0x0100, []byte{0x00, 0x01}},
	}
	for _, tt := range tests {
		result := u.PackUint16LE(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("PackUint16LE(0x%X) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestPackUint16BE(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		input    int
		expected []byte
	}{
		{0x1234, []byte{0x12, 0x34}},
		{0, []byte{0x00, 0x00}},
		{0xFFFF, []byte{0xFF, 0xFF}},
		{0x0100, []byte{0x01, 0x00}},
	}
	for _, tt := range tests {
		result := u.PackUint16BE(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("PackUint16BE(0x%X) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestPackUint32LE(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		input    int
		expected []byte
	}{
		{0x12345678, []byte{0x78, 0x56, 0x34, 0x12}},
		{0, []byte{0x00, 0x00, 0x00, 0x00}},
		{0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{1, []byte{0x01, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		result := u.PackUint32LE(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("PackUint32LE(0x%X) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestPackUint32BE(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		input    int
		expected []byte
	}{
		{0x12345678, []byte{0x12, 0x34, 0x56, 0x78}},
		{0, []byte{0x00, 0x00, 0x00, 0x00}},
		{0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{1, []byte{0x00, 0x00, 0x00, 0x01}},
	}
	for _, tt := range tests {
		result := u.PackUint32BE(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("PackUint32BE(0x%X) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestPackUint64LE(t *testing.T) {
	u := &Utils{}
	result := u.PackUint64LE(0x123456789ABCDEF0)
	expected := []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}
	if !bytes.Equal(result, expected) {
		t.Errorf("PackUint64LE = %v, want %v", result, expected)
	}
}

func TestPackUint64BE(t *testing.T) {
	u := &Utils{}
	result := u.PackUint64BE(0x123456789ABCDEF0)
	expected := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	if !bytes.Equal(result, expected) {
		t.Errorf("PackUint64BE = %v, want %v", result, expected)
	}
}

func TestUnpackUint16LE(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		data     []byte
		offset   int
		expected int
	}{
		{[]byte{0x34, 0x12}, 0, 0x1234},
		{[]byte{0x00, 0x00, 0x34, 0x12}, 2, 0x1234},
		{[]byte{0xFF, 0xFF}, 0, 0xFFFF},
		{[]byte{0x00}, 0, 0},
	}
	for _, tt := range tests {
		result := u.UnpackUint16LE(tt.data, tt.offset)
		if result != tt.expected {
			t.Errorf("UnpackUint16LE(%v, %d) = 0x%X, want 0x%X", tt.data, tt.offset, result, tt.expected)
		}
	}
}

func TestUnpackUint16BE(t *testing.T) {
	u := &Utils{}
	result := u.UnpackUint16BE([]byte{0x12, 0x34}, 0)
	if result != 0x1234 {
		t.Errorf("UnpackUint16BE = 0x%X, want 0x1234", result)
	}
}

func TestUnpackUint32LE(t *testing.T) {
	u := &Utils{}
	tests := []struct {
		data     []byte
		offset   int
		expected int
	}{
		{[]byte{0x78, 0x56, 0x34, 0x12}, 0, 0x12345678},
		{[]byte{0x00, 0x00, 0x78, 0x56, 0x34, 0x12}, 2, 0x12345678},
		{[]byte{0x01, 0x00, 0x00, 0x00}, 0, 1},
		{[]byte{0x00, 0x00, 0x00}, 0, 0},
	}
	for _, tt := range tests {
		result := u.UnpackUint32LE(tt.data, tt.offset)
		if result != tt.expected {
			t.Errorf("UnpackUint32LE(%v, %d) = 0x%X, want 0x%X", tt.data, tt.offset, result, tt.expected)
		}
	}
}

func TestUnpackUint32BE(t *testing.T) {
	u := &Utils{}
	result := u.UnpackUint32BE([]byte{0x12, 0x34, 0x56, 0x78}, 0)
	if result != 0x12345678 {
		t.Errorf("UnpackUint32BE = 0x%X, want 0x12345678", result)
	}
}

func TestUnpackUint64LE(t *testing.T) {
	u := &Utils{}
	data := []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}
	result := u.UnpackUint64LE(data, 0)
	expected := int64(0x123456789ABCDEF0)
	if result != expected {
		t.Errorf("UnpackUint64LE = 0x%X, want 0x%X", result, expected)
	}
}

func TestUnpackUint64BE(t *testing.T) {
	u := &Utils{}
	data := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	result := u.UnpackUint64BE(data, 0)
	expected := int64(0x123456789ABCDEF0)
	if result != expected {
		t.Errorf("UnpackUint64BE = 0x%X, want 0x%X", result, expected)
	}
}

func TestUnpackBoundaryCheck(t *testing.T) {
	u := &Utils{}
	if u.UnpackUint16LE([]byte{0x00}, 0) != 0 {
		t.Errorf("UnpackUint16LE should return 0 for short data")
	}
	if u.UnpackUint32LE([]byte{0x00, 0x00}, 0) != 0 {
		t.Errorf("UnpackUint32LE should return 0 for short data")
	}
	if u.UnpackUint64LE([]byte{0x00, 0x00, 0x00, 0x00}, 0) != 0 {
		t.Errorf("UnpackUint64LE should return 0 for short data")
	}
}

func TestConcatBytes(t *testing.T) {
	u := &Utils{}
	result := u.ConcatBytes([]byte{0x01, 0x02}, []byte{0x03, 0x04}, []byte{0x05})
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(result, expected) {
		t.Errorf("ConcatBytes = %v, want %v", result, expected)
	}
}

func TestConcatBytesEmpty(t *testing.T) {
	u := &Utils{}
	result := u.ConcatBytes()
	if len(result) != 0 {
		t.Errorf("ConcatBytes() = %v, want empty", result)
	}
	result2 := u.ConcatBytes([]byte{0x01}, []byte{}, []byte{0x02})
	expected := []byte{0x01, 0x02}
	if !bytes.Equal(result2, expected) {
		t.Errorf("ConcatBytes with empty = %v, want %v", result2, expected)
	}
}

func TestStringToBytes(t *testing.T) {
	u := &Utils{}
	result := u.StringToBytes("hello")
	expected := []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}
	if !bytes.Equal(result, expected) {
		t.Errorf("StringToBytes = %v, want %v", result, expected)
	}
}

func TestBytesToString(t *testing.T) {
	u := &Utils{}
	result := u.BytesToString([]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f})
	if result != "hello" {
		t.Errorf("BytesToString = %q, want %q", result, "hello")
	}
}

func TestToBytes(t *testing.T) {
	u := &Utils{}
	result := u.ToBytes([]byte{0x41, 0x42})
	expected := []byte{0x41, 0x42}
	if !bytes.Equal(result, expected) {
		t.Errorf("ToBytes([]byte) = %v, want %v", result, expected)
	}

	result = u.ToBytes("AB")
	if !bytes.Equal(result, expected) {
		t.Errorf("ToBytes(string) = %v, want %v", result, expected)
	}

	result = u.ToBytes([]interface{}{int64(0x41), int64(0x42)})
	if !bytes.Equal(result, expected) {
		t.Errorf("ToBytes([]interface{}) = %v, want %v", result, expected)
	}

	result = u.ToBytes([]interface{}{float64(0x41), float64(0x42)})
	if !bytes.Equal(result, expected) {
		t.Errorf("ToBytes([]interface{} float64) = %v, want %v", result, expected)
	}
}

func TestToBytesNil(t *testing.T) {
	u := &Utils{}
	result := u.ToBytes(123)
	if result != nil {
		t.Errorf("ToBytes(unsupported) = %v, want nil", result)
	}
}

func TestP8Alias(t *testing.T) {
	u := &Utils{}
	if !bytes.Equal(u.P8(0x41), u.PackUint8(0x41)) {
		t.Errorf("P8 should equal PackUint8")
	}
}

func TestP16Aliases(t *testing.T) {
	u := &Utils{}
	if !bytes.Equal(u.P16(0x1234), u.PackUint16LE(0x1234)) {
		t.Errorf("P16 should equal PackUint16LE")
	}
	if !bytes.Equal(u.P16BE(0x1234), u.PackUint16BE(0x1234)) {
		t.Errorf("P16BE should equal PackUint16BE")
	}
}

func TestP32Aliases(t *testing.T) {
	u := &Utils{}
	if !bytes.Equal(u.P32(0x12345678), u.PackUint32LE(0x12345678)) {
		t.Errorf("P32 should equal PackUint32LE")
	}
	if !bytes.Equal(u.P32BE(0x12345678), u.PackUint32BE(0x12345678)) {
		t.Errorf("P32BE should equal PackUint32BE")
	}
}

func TestP64Aliases(t *testing.T) {
	u := &Utils{}
	if !bytes.Equal(u.P64(0x123456789ABCDEF0), u.PackUint64LE(0x123456789ABCDEF0)) {
		t.Errorf("P64 should equal PackUint64LE")
	}
	if !bytes.Equal(u.P64BE(0x123456789ABCDEF0), u.PackUint64BE(0x123456789ABCDEF0)) {
		t.Errorf("P64BE should equal PackUint64BE")
	}
}

func TestU16Aliases(t *testing.T) {
	u := &Utils{}
	data := []byte{0x34, 0x12}
	if u.U16(data, 0) != u.UnpackUint16LE(data, 0) {
		t.Errorf("U16 should equal UnpackUint16LE")
	}
	dataBE := []byte{0x12, 0x34}
	if u.U16BE(dataBE, 0) != u.UnpackUint16BE(dataBE, 0) {
		t.Errorf("U16BE should equal UnpackUint16BE")
	}
}

func TestU32Aliases(t *testing.T) {
	u := &Utils{}
	data := []byte{0x78, 0x56, 0x34, 0x12}
	if u.U32(data, 0) != u.UnpackUint32LE(data, 0) {
		t.Errorf("U32 should equal UnpackUint32LE")
	}
	dataBE := []byte{0x12, 0x34, 0x56, 0x78}
	if u.U32BE(dataBE, 0) != u.UnpackUint32BE(dataBE, 0) {
		t.Errorf("U32BE should equal UnpackUint32BE")
	}
}

func TestU64Aliases(t *testing.T) {
	u := &Utils{}
	data := []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}
	if u.U64(data, 0) != u.UnpackUint64LE(data, 0) {
		t.Errorf("U64 should equal UnpackUint64LE")
	}
	dataBE := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	if u.U64BE(dataBE, 0) != u.UnpackUint64BE(dataBE, 0) {
		t.Errorf("U64BE should equal UnpackUint64BE")
	}
}

func TestFlat(t *testing.T) {
	u := &Utils{}
	result := u.Flat(
		[]byte{0x01, 0x02},
		"AB",
		0x03,
		[]interface{}{float64(0x04), float64(0x05)},
	)
	expected := []byte{0x01, 0x02, 0x41, 0x42, 0x03, 0x04, 0x05}
	if !bytes.Equal(result, expected) {
		t.Errorf("Flat = %v, want %v", result, expected)
	}
}

func TestFlatEmpty(t *testing.T) {
	u := &Utils{}
	result := u.Flat()
	if len(result) != 0 {
		t.Errorf("Flat() = %v, want empty", result)
	}
}

func TestFlatWithPackedValues(t *testing.T) {
	u := &Utils{}
	result := u.Flat(
		u.P32(0x12345678),
		u.P16(0xABCD),
		u.P8(0xFF),
	)
	expected := []byte{0x78, 0x56, 0x34, 0x12, 0xCD, 0xAB, 0xFF}
	if !bytes.Equal(result, expected) {
		t.Errorf("Flat with packed = %v, want %v", result, expected)
	}
}

func TestFlatInt64(t *testing.T) {
	u := &Utils{}
	result := u.Flat(int64(0x41))
	expected := []byte{0x41}
	if !bytes.Equal(result, expected) {
		t.Errorf("Flat(int64) = %v, want %v", result, expected)
	}
}

func TestFlatMixedJSArray(t *testing.T) {
	u := &Utils{}
	result := u.Flat(
		[]interface{}{int(0x41), int64(0x42), float64(0x43)},
	)
	expected := []byte{0x41, 0x42, 0x43}
	if !bytes.Equal(result, expected) {
		t.Errorf("Flat mixed JS array = %v, want %v", result, expected)
	}
}

func TestPackUnpackRoundtrip(t *testing.T) {
	u := &Utils{}
	original16 := 0x1234
	packed16 := u.P16(original16)
	unpacked16 := u.U16(packed16, 0)
	if unpacked16 != original16 {
		t.Errorf("P16/U16 roundtrip: got 0x%X, want 0x%X", unpacked16, original16)
	}

	original32 := 0x12345678
	packed32 := u.P32(original32)
	unpacked32 := u.U32(packed32, 0)
	if unpacked32 != original32 {
		t.Errorf("P32/U32 roundtrip: got 0x%X, want 0x%X", unpacked32, original32)
	}

	original64 := int64(0x123456789ABCDEF0)
	packed64 := u.P64(original64)
	unpacked64 := u.U64(packed64, 0)
	if unpacked64 != original64 {
		t.Errorf("P64/U64 roundtrip: got 0x%X, want 0x%X", unpacked64, original64)
	}
}
