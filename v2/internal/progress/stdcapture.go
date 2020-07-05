package progress

/**
  Inspired by the https://github.com/PumpkinSeed/cage module
 */
import (
	"bytes"
	"context"
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

	data         string
	channel      chan string

	sync		 sync.WaitGroup

	Data []string
}

var(
	mutex = &sync.Mutex{}
)

func startStdCapture() *captureData {
	mutex.Lock()

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

		channel: make(chan string),
	}

	os.Stdout = c.writerStdout
	os.Stderr = c.writerStderr

	c.sync.Add(2)

	go func( wg *sync.WaitGroup, out chan string, readerStdout *os.File, readerStderr *os.File) {
		defer wg.Done()

		var bufStdout bytes.Buffer
		_, _ = io.Copy(&bufStdout, readerStdout)
		if bufStdout.Len() > 0 {
			out <- bufStdout.String()
		}

		var bufStderr bytes.Buffer
		_, _ = io.Copy(&bufStderr, readerStderr)
		if bufStderr.Len() > 0 {
			out <- bufStderr.String()
		}
	}(&c.sync, c.channel, rStdout, rStderr)

	go func(wg *sync.WaitGroup, c *captureData) {
		ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Millisecond)
		defer cancel()

		select {
		case out := <-c.channel:
			c.data += out
			wg.Done()
		case <-ctx.Done():
			wg.Done()
			break
		}
	}(&c.sync, c)

	return c
}

func stopStdCapture(c *captureData) {
	_ = c.writerStdout.Close()
	_ = c.writerStderr.Close()

	c.sync.Wait()

	close(c.channel)

	os.Stdout = c.backupStdout
	os.Stderr = c.backupStderr

	c.Data = strings.Split(c.data, "\n")
	if c.Data[len(c.Data)-1] == "" {
		c.Data = c.Data[:len(c.Data)-1]
	}

	mutex.Unlock()
}
