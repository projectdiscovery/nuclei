package progress

/**
  Inspired by the https://github.com/PumpkinSeed/cage module
*/
import (
	"bufio"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

const (
	fourMegas = 4 * 1024
	two       = 2
)

type captureData struct {
	backupStdout   *os.File
	writerStdout   *os.File
	backupStderr   *os.File
	writerStderr   *os.File
	waitFinishRead *sync.WaitGroup
}

func startCapture(writeLocker sync.Locker, stdout, stderr *strings.Builder) *captureData {
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

		waitFinishRead: &sync.WaitGroup{},
	}

	os.Stdout = c.writerStdout
	os.Stderr = c.writerStderr

	stdCopy := func(builder *strings.Builder, reader *os.File, waitGroup *sync.WaitGroup) {
		r := bufio.NewReader(reader)
		buf := make([]byte, 0, fourMegas)

		for {
			n, err := r.Read(buf[:cap(buf)])
			buf = buf[:n]

			if n == 0 {
				if err == nil {
					continue
				}

				if err == io.EOF {
					waitGroup.Done()
					break
				}

				waitGroup.Done()
				gologger.Fatalf("stdcapture error: %s", err)
			}

			if err != nil && err != io.EOF {
				waitGroup.Done()
				gologger.Fatalf("stdcapture error: %s", err)
			}

			writeLocker.Lock()
			builder.Write(buf)
			writeLocker.Unlock()
		}
	}

	c.waitFinishRead.Add(two)

	go stdCopy(stdout, rStdout, c.waitFinishRead)
	go stdCopy(stderr, rStderr, c.waitFinishRead)

	return c
}

func stopCapture(c *captureData) {
	_ = c.writerStdout.Close()
	_ = c.writerStderr.Close()

	c.waitFinishRead.Wait()

	os.Stdout = c.backupStdout
	os.Stderr = c.backupStderr
}
