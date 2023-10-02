//go:build debug
// +build debug

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"
)

func init() {
	log.Println("available env configs:")
	log.Println("MEM_PROFILE_DIR - directory to write memory profiles to")
	log.Println("CPU_PROFILE_DIR - directory to write cpu profiles to")
	log.Println("PPROF_TIME - polling time for cpu and memory profiles (with unit ex: 10s)")
	log.Println("MEM_PROFILE_RATE - memory profiling rate (default 4096)")
	memfile := os.Getenv("MEM_PROFILE_DIR")
	cpuProfile := os.Getenv("CPU_PROFILE_DIR")
	pproftime := os.Getenv("PPROF_TIME")
	if cpuProfile == "" {
		cpuProfile = "cpuprofile"
	}
	if memfile == "" {
		memfile = "memdump"
	}

	tickerTime := time.Duration(3 * time.Second)
	if pproftime != "" {
		d, err := time.ParseDuration(pproftime)
		if err == nil {
			tickerTime = d
		}
	}

	mempprofRate := 4096
	tmp := os.Getenv("MEM_PROFILE_RATE")
	if tmp != "" {
		tmpint, err := strconv.Atoi(tmp)
		if err == nil {
			mempprofRate = tmpint
		}
	}

	log.Printf("GOOS: %v\n", runtime.GOOS)
	log.Printf("GOARCH: %v\n", runtime.GOARCH)

	_ = os.MkdirAll(memfile, 0755)
	_ = os.MkdirAll(cpuProfile, 0755)

	runtime.MemProfileRate = mempprofRate
	log.Printf("profile: memory profiling enabled (rate %d), %s\n", runtime.MemProfileRate, memProfile)
	log.Printf("profile: ticker enabled (rate %s)\n", tickerTime)

	// cpu ticker and profiler
	go func() {
		ticker := time.NewTicker(tickerTime)
		count := 0
		buff := bytes.Buffer{}
		log.Printf("profile: cpu profiling enabled (ticker %s)\n", tickerTime)
		for {
			err := pprof.StartCPUProfile(&buff)
			if err != nil {
				log.Fatalf("profile: could not start cpu profile: %s\n", err)
			}
			<-ticker.C
			pprof.StopCPUProfile()
			if err := os.WriteFile(filepath.Join(cpuProfile, "cpuprofile-t"+strconv.Itoa(count)+".out"), buff.Bytes(), 0755); err != nil {
				log.Fatalf("profile: could not write cpu profile: %s\n", err)
			}
			buff.Reset()
			count++
		}
	}()

	// memory ticker and profiler
	go func() {
		ticker := time.NewTicker(tickerTime)
		count := 0
		log.Printf("profile: memory profiling enabled (ticker %s)\n", tickerTime)
		for {
			<-ticker.C
			var buff bytes.Buffer
			if err := pprof.WriteHeapProfile(&buff); err != nil {
				log.Printf("profile: could not write memory profile: %s\n", err)
			}
			err := os.WriteFile(filepath.ToSlash(filepath.Join(memfile, "memprofile-t"+strconv.Itoa(count)+".out")), buff.Bytes(), 0755)
			if err != nil {
				log.Printf("profile: could not write memory profile: %s\n", err)
			}
			count++
		}
	}()
}
