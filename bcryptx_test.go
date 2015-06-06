package bcryptx_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/codemodus/bcryptx"
)

const (
	errFmtGotWant = "Time = %v, want T > %v and T < %v"
	testPass      = "012Abc!@#z"
)

var (
	errNoErr = errors.New("No error returned.")
)

func Example() {
	bcxOpts := &bcryptx.Options{
		GenQuickMaxTime:  time.Millisecond * 400,  // default is 500
		GenStrongMaxTime: time.Millisecond * 1600, // default is 2000
		GenConcurrency:   1,                       // default is 2
	}

	// To use defaults, provide nil instead of a bcryptx.Options object.
	bcx := bcryptx.New(bcxOpts)
	if err := bcx.Tune(); err != nil {
		fmt.Println(err)
	}

	hash, err := bcx.GenQuickFromPass("12345")
	if err != nil {
		fmt.Println(err)
	}

	if err := bcx.CompareHashAndPass(hash, "spaceballs"); err != nil {
		fmt.Println(`Generated hash for "12345", tested for "spaceballs".`)
	}

	if ok := bcx.IsCostStrong(hash); !ok {
		fmt.Println("Hashed quick, wanted strong.")
	}

	// Output:
	// Generated hash for "12345", tested for "spaceballs".
	// Hashed quick, wanted strong.
}

func TestNilSetupNoTune(t *testing.T) {
	bcx := bcryptx.New(nil)
	h1, err := bcx.GenQuickFromPass(testPass)
	if err != nil {
		t.Fatal(err)
	}
	if err = bcx.CompareHashAndPass(h1, testPass); err != nil {
		t.Fatal(err)
	}

	if ok := bcx.IsCostQuick(h1); !ok {
		t.Fatal(errors.New("cost should be quickCost"))
	}
	if err := bcx.ValidateHash(h1); err != nil {
		t.Fatal(err)
	}
	if ok := bcx.IsCostQuick(testPass); ok {
		t.Fatal(errNoErr)
	}
	if err := bcx.ValidateHash(testPass); err == nil {
		t.Fatal(errNoErr)
	}

	bcx = bcryptx.New(nil)
	h2, err := bcx.GenStrongFromPass(testPass)
	if err != nil {
		t.Fatal(err)
	}
	if err = bcx.CompareHashAndPass(h2, testPass); err != nil {
		t.Fatal(err)
	}
	if ok := bcx.IsCostStrong(h2); !ok {
		t.Fatal(err)
	}
	if ok := bcx.IsCostStrong(h1); ok {
		t.Fatal(errNoErr)
	}
}

func TestCustomTimeSetup(t *testing.T) {
	var tests = []struct {
		qt  time.Duration
		st  time.Duration
		exc bool
	}{
		{time.Millisecond * 50, time.Millisecond * 200, false},
		{time.Millisecond * 200, time.Millisecond * 800, false},
		{bcryptx.GenQuickMaxTime, bcryptx.GenStrongMaxTime, false},
		{time.Millisecond * 999999999, time.Millisecond * 999999999, true},
	}

	for _, v := range tests {
		bcxOpts := &bcryptx.Options{
			GenQuickMaxTime:  v.qt,
			GenStrongMaxTime: v.st,
		}

		bcx := bcryptx.New(bcxOpts)
		err := bcx.Tune()
		if !v.exc && err != nil {
			t.Fatal(err)
		}
		if v.exc && err == nil {
			t.Error(errNoErr)
		}

		if v.exc {
			if ok := bcx.IsCostQuick(""); ok {
				t.Fatal("should not be ok")
			}
			if ok := bcx.IsCostStrong(""); ok {
				t.Fatal("should not be ok")
			}
		}

		t1 := time.Now()
		_, err = bcx.GenQuickFromPass(testPass)
		if !v.exc && err != nil {
			t.Fatal(err)
		}
		if v.exc && err == nil {
				t.Error(errNoErr)
		}
		got1 := time.Since(t1)

		t2 := time.Now()
		_, err = bcx.GenStrongFromPass(testPass)
		if !v.exc && err != nil {
			t.Fatal(err)
		}
		if v.exc {
			if err == nil {
				t.Error(errNoErr)
			}
			continue
		}
		got2 := time.Since(t2)

		wantLow := v.qt / 2
		wantHigh := v.qt
		if got1 < wantLow || got1 > wantHigh {
			t.Errorf(errFmtGotWant, got1, wantLow, wantHigh)
		}

		wantLow = v.st / 2
		wantHigh = v.st
		if got2 < wantLow || got2 > wantHigh {
			t.Errorf(errFmtGotWant, got2, wantLow, wantHigh)
		}
	}
}
