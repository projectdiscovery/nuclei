//go:build debug
// +build debug

package main

import (
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"
)

func init() {
	memfile := os.Getenv("PPROF_FILE")
	cpuProfile := os.Getenv("CPU_PROFILE")
	if cpuProfile == "" {
		cpuProfile = "cpuprofile.out"
	}
	if memfile == "" {
		memfile = "memdump.out"
	}
	log.Printf("GOOS: %v\n", runtime.GOOS)
	log.Printf("GOARCH: %v\n", runtime.GOARCH)

	pproftime := os.Getenv("PPROF_TIME") // in seconds

	var ticker *time.Ticker
	if pproftime != "" {
		d, err := time.ParseDuration(pproftime)
		if err == nil {
			ticker = time.NewTicker(d)
			log.Printf("profile: tick every %v\n", d.String())
		}
	}
	if ticker == nil {
		ticker = time.NewTicker(1 * time.Second) // tick every second
		log.Println("profile: tick every second")
	}
	f, err := os.Create(memfile)
	if err != nil {
		log.Fatalf("profile: could not create memory profile %q: %v", memProfile, err)
	}
	cpuf, err := os.Create(cpuProfile)
	if err != nil {
		log.Fatalf("profile: could not create cpu profile %q: %v", cpuProfile, err)
	}
	pprof.StartCPUProfile(cpuf)
	mempprofRate := 4096
	tmp := os.Getenv("MEM_PROFILE_RATE")
	if tmp != "" {
		tmpint, err := strconv.Atoi(tmp)
		if err == nil {
			mempprofRate = tmpint
		}
	}
	runtime.MemProfileRate = mempprofRate
	log.Printf("profile: memory profiling enabled (rate %d), %s\n", runtime.MemProfileRate, memProfile)

	go func() {
		for {
			<-ticker.C
			pprof.Lookup("heap").WriteTo(f, 0)
			pprof.StopCPUProfile()
			pprof.StartCPUProfile(cpuf)
		}
	}()
}
