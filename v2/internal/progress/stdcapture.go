package progress

/**
  Inspired by the https://github.com/PumpkinSeed/cage module
 */
import (
	"bytes"
	"io"
	"os"
	"sync"
)

type captureData struct {
	backupStdout *os.File
	writerStdout *os.File
	backupStderr *os.File
	writerStderr *os.File

	DataStdOut *bytes.Buffer
	DataStdErr *bytes.Buffer

	outStdout  chan []byte
	outStderr  chan []byte
}

func startStdCapture() *captureData {
	rStdout, wStdout, errStdout := os.Pipe()
	if errStdout != nil {
		panic(errStdout)
	}

	rStderr, wStderr, errStderr := os.Pipe()
	if errStderr != nil {
		panic(errStderr)
	}

	c := &captureData{
		backupStdout: os.Stdout,
		writerStdout: wStdout,

		backupStderr: os.Stderr,
		writerStderr: wStderr,

		outStdout: make(chan []byte),
		outStderr: make(chan []byte),

		DataStdOut: &bytes.Buffer{},
		DataStdErr: &bytes.Buffer{},
	}

	os.Stdout = c.writerStdout
	os.Stderr = c.writerStderr

	stdCopy := func(out chan<- []byte, reader *os.File) {
		var buffer bytes.Buffer
		_, _ = io.Copy(&buffer, reader)
		if buffer.Len() > 0 {
			out <- buffer.Bytes()
		}
		close(out)
	}

	go stdCopy(c.outStdout, rStdout)
	go stdCopy(c.outStderr, rStderr)

	return c
}

func stopStdCapture(c *captureData) {
	_ = c.writerStdout.Close()
	_ = c.writerStderr.Close()

	var wg sync.WaitGroup

	stdRead := func(in <-chan []byte, outData *bytes.Buffer) {
		defer wg.Done()

		for {
			out, more := <-in
			if more {
				outData.Write(out)
			} else {
				return
			}
		}
	}

	wg.Add(2)
	go stdRead(c.outStdout, c.DataStdOut)
	go stdRead(c.outStderr, c.DataStdErr)
	wg.Wait()

	os.Stdout = c.backupStdout
	os.Stderr = c.backupStderr
}
