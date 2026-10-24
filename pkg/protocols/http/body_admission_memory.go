package http

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func cgroupMemoryLimit(procPath, root string) (uint64, error) {
	contents, err := os.ReadFile(procPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	var lowest uint64
	for line := range strings.SplitSeq(string(contents), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		controllerRoot := root
		limitFile := "memory.max"
		if fields[1] != "" {
			if !strings.Contains(","+fields[1]+",", ",memory,") {
				continue
			}
			controllerRoot = filepath.Join(root, "memory")
			limitFile = "memory.limit_in_bytes"
		}
		limit, err := memoryLimitInHierarchy(controllerRoot, fields[2], limitFile)
		if err != nil {
			return 0, err
		}
		if limit > 0 && (lowest == 0 || limit < lowest) {
			lowest = limit
		}
	}
	return lowest, nil
}

func memoryLimitInHierarchy(root, cgroupPath, limitFile string) (uint64, error) {
	root = filepath.Clean(root)
	current := filepath.Join(root, strings.TrimPrefix(filepath.Clean("/"+cgroupPath), "/"))
	var lowest uint64
	for {
		contents, err := os.ReadFile(filepath.Join(current, limitFile))
		if err == nil {
			value := strings.TrimSpace(string(contents))
			if value != "max" {
				limit, parseErr := strconv.ParseUint(value, 10, 64)
				if parseErr != nil || limit == 0 {
					return 0, fmt.Errorf("invalid cgroup memory limit %q in %s", value, current)
				}
				if lowest == 0 || limit < lowest {
					lowest = limit
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		if current == root {
			break
		}
		current = filepath.Dir(current)
	}
	return lowest, nil
}
