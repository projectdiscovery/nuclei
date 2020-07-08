package progress

/**
  Inspired by the https://github.com/PumpkinSeed/cage module
 */
import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type captureData struct {
	backupStdout *os.File
	writerStdout *os.File
	backupStderr *os.File
	writerStderr *os.File

	dataStdout string
	dataStderr string
	outStdout  chan []byte
	outStderr  chan []byte

	//sync		 sync.WaitGroup

	DataStdOut []string
	DataStdErr []string
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
	}

	os.Stdout = c.writerStdout
	os.Stderr = c.writerStderr

	stdCopy := func(out chan<- []byte, reader *os.File) {
		var buffer bytes.Buffer
		_, _ = io.Copy(&buffer, reader)
		if buffer.Len() > 0 {
			out <- buffer.Bytes()
		}
	}

	go stdCopy(c.outStdout, rStdout)
	go stdCopy(c.outStderr, rStderr)

	return c
}

func stopStdCapture(c *captureData) {
	_ = c.writerStdout.Close()
	_ = c.writerStderr.Close()

	var wg sync.WaitGroup

	stdRead := func(in <-chan []byte, outString *string, outArray *[]string) {
		defer wg.Done()

		select {
		case out := <-in:
			*outString = string(out)
			*outArray = strings.Split(*outString, "\n")
			if (*outArray)[len(*outArray)-1] == "" {
				*outArray = (*outArray)[:len(*outArray)-1]
			}
		case <-time.After(50 * time.Millisecond):
		}
	}

	wg.Add(2)
	go stdRead(c.outStdout, &c.dataStdout, &c.DataStdOut)
	go stdRead(c.outStderr, &c.dataStderr, &c.DataStdErr)
	wg.Wait()

	os.Stdout = c.backupStdout
	os.Stderr = c.backupStderr
}
