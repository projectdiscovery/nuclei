package runner

import "testing"

func TestIsUrlWithScheme(t *testing.T) {
	t.Run("Testing with invalid format url", func(t *testing.T) {
		isInvalid1 := isUrlWithScheme("/fooo")
		if isInvalid1 != false {
			t.Errorf("expected result  is false but result %t", isInvalid1)
			t.Fail()
		}
		isInvalid2 := isUrlWithScheme("google.com")
		if isInvalid2 != false {
			t.Errorf("expected result  is false but result %t", isInvalid2)
			t.Fail()
		}
		isInvalid3 := isUrlWithScheme("wwww.google")
		if isInvalid3 != false {
			t.Errorf("expected result  is false but result %t", isInvalid3)
			t.Fail()
		}
	})

	t.Run("Testing with valid format url", func(t *testing.T) {
		isValid := isUrlWithScheme("https://google.com")
		if isValid != true {
			t.Errorf("expected result  is true but result %t", isValid)
			t.Fail()
		}
	})
}
