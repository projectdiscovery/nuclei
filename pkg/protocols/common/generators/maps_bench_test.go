package generators

import (
	"fmt"
	"testing"
)

func BenchmarkMergeMaps(b *testing.B) {
	map1 := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
		"key4": "value4",
		"key5": "value5",
	}
	map2 := map[string]interface{}{
		"key6":  "value6",
		"key7":  "value7",
		"key8":  "value8",
		"key9":  "value9",
		"key10": "value10",
	}
	map3 := map[string]interface{}{
		"key11": "value11",
		"key12": "value12",
		"key13": "value13",
	}

	for i := 1; i <= 3; i++ {
		b.Run(fmt.Sprintf("%d-maps", i), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				switch i {
				case 1:
					_ = MergeMaps(map1)
				case 2:
					_ = MergeMaps(map1, map2)
				case 3:
					_ = MergeMaps(map1, map2, map3)
				}
			}
		})
	}
}

func BenchmarkCopyMap(b *testing.B) {
	map1 := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
		"key4": "value4",
		"key5": "value5",
	}

	for i := 1; i <= 1; i++ {
		b.Run(fmt.Sprintf("%d-maps", i), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				switch i {
				case 1:
					_ = CopyMap(map1)
				}
			}
		})
	}
}

func BenchmarkMergeMapsInto(b *testing.B) {
	map1 := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
		"key4": "value4",
		"key5": "value5",
	}
	map2 := map[string]interface{}{
		"key6":  "value6",
		"key7":  "value7",
		"key8":  "value8",
		"key9":  "value9",
		"key10": "value10",
	}
	map3 := map[string]interface{}{
		"key11": "value11",
		"key12": "value12",
		"key13": "value13",
	}
	map4 := map[string]interface{}{
		"key14": "value14",
		"key15": "value15",
		"key16": "value16",
	}

	for i := 1; i <= 3; i++ {
		b.Run(fmt.Sprintf("%d-maps", i), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				switch i {
				case 1:
					MergeMapsInto(map1, map2)
				case 2:
					MergeMapsInto(map1, map2, map3)
				case 3:
					MergeMapsInto(map1, map2, map3, map4)
				}
			}
		})
	}
}
