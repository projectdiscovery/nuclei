package compress

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

func compressed(t *testing.T, encoding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch encoding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "br":
		w = brotli.NewWriter(&buf)
	case "zstd":
		zw, err := zstd.NewWriter(&buf)
		require.NoError(t, err)
		w = zw
	case "identity":
		return data
	}
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func decodeInChunks(t *testing.T, d *Decoder, input []byte) ([]byte, error) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	var decoded []byte
	collect := func(out []byte, err error) bool {
		require.LessOrEqual(t, len(out), maxDecodedChunk+64<<10)
		decoded = append(decoded, out...)
		return err == nil && len(out) > 0
	}
	drain := func(out []byte, err error) error {
		for collect(out, err) {
			out, err = d.Read()
		}
		return err
	}
	for len(input) > 0 {
		n := min(len(input), 1+rng.Intn(70000))
		out, err := d.Write(input[:n])
		if err := drain(out, err); err != nil {
			return decoded, err
		}
		input = input[n:]
	}
	out, err := d.Close()
	return decoded, drain(out, err)
}

func TestDecoderMatchesWholeBodyDecode(t *testing.T) {
	data := bytes.Repeat([]byte("nuclei streaming decoder "), 400000)
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			d, err := NewDecoder(t.Context(), encoding)
			require.NoError(t, err)
			decoded, err := decodeInChunks(t, d, compressed(t, encoding, data))
			require.NoError(t, err)
			require.Equal(t, data, decoded)
		})
	}
}

func chunked(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := httputil.NewChunkedWriter(&buf)
	for len(data) > 0 {
		n := min(len(data), 8000)
		_, err := w.Write(data[:n])
		require.NoError(t, err)
		data = data[n:]
	}
	require.NoError(t, w.Close())
	buf.WriteString("\r\n")
	return buf.Bytes()
}

func TestDecoderDecodesChunkedTransfer(t *testing.T) {
	data := bytes.Repeat([]byte("nuclei chunked decoder "), 400000)
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			d, err := NewDecoder(t.Context(), encoding+", chunked")
			require.NoError(t, err)
			decoded, err := decodeInChunks(t, d, chunked(t, compressed(t, encoding, data)))
			require.NoError(t, err)
			require.Equal(t, data, decoded)
		})
	}
}

func TestDecoderFinishesAtLastChunk(t *testing.T) {
	data := bytes.Repeat([]byte("finished "), 1000)
	d, err := NewDecoder(t.Context(), "gzip, chunked")
	require.NoError(t, err)
	input := chunked(t, compressed(t, "gzip", data))

	half := len(input) / 2
	_, err = d.Write(input[:half])
	require.NoError(t, err)
	require.False(t, d.Finished())

	out, err := d.Write(input[half:])
	require.NoError(t, err)
	var decoded []byte
	for ; len(out) > 0; out, err = d.Read() {
		decoded = append(decoded, out...)
	}
	require.NoError(t, err)
	require.Equal(t, data, decoded)
	require.True(t, d.Finished(), "decoder must finish without Close once the last chunk arrives")
}

func TestDecoderAppliesCodingsInReverse(t *testing.T) {
	data := bytes.Repeat([]byte("two codings "), 100000)
	input := compressed(t, "br", compressed(t, "gzip", data))
	d, err := NewDecoder(t.Context(), "gzip, br")
	require.NoError(t, err)
	decoded, err := decodeInChunks(t, d, input)
	require.NoError(t, err)
	require.Equal(t, data, decoded)
}

func TestDecoderReportsTruncatedStream(t *testing.T) {
	data := bytes.Repeat([]byte("truncated "), 200000)
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd", "identity, chunked"} {
		t.Run(encoding, func(t *testing.T) {
			var input []byte
			if encoding == "identity, chunked" {
				input = chunked(t, data)
			} else {
				input = compressed(t, encoding, data)
			}
			d, err := NewDecoder(t.Context(), encoding)
			require.NoError(t, err)
			decoded, err := decodeInChunks(t, d, input[:len(input)/2])
			require.Error(t, err)
			require.True(t, bytes.HasPrefix(data, decoded), "bytes before the cut must still be handed back")
		})
	}
}

func TestDecoderStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	d, err := NewDecoder(ctx, "gzip")
	require.NoError(t, err)
	_, err = d.Write(compressed(t, "gzip", []byte("abandoned"))[:5])
	require.NoError(t, err)

	cancel()
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("decode goroutine outlived its context")
	}
}

func TestNewDecoderRejectsUnknownEncoding(t *testing.T) {
	_, err := NewDecoder(t.Context(), "compress")
	require.Error(t, err)
	_, err = NewDecoder(t.Context(), "gzip, compress")
	require.Error(t, err)
}

func TestDecoderNotCreatedByNewDecoderErrors(t *testing.T) {
	var d Decoder
	_, err := d.Write([]byte("x"))
	require.ErrorIs(t, err, errNotCreatedByNewDecoder)
	_, err = d.Read()
	require.ErrorIs(t, err, errNotCreatedByNewDecoder)
	_, err = d.Close()
	require.ErrorIs(t, err, errNotCreatedByNewDecoder)
}
