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

func TestNilSetupNoTuneWithHelpers(t *testing.T) {
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

func TestNilSetupHashTimes(t *testing.T) {
	bcx := bcryptx.New(nil)
	if err := bcx.Tune(); err != nil {
		t.Fatal(err)
	}

	t1 := time.Now()
	if _, err := bcx.GenQuickFromPass(testPass); err != nil {
		t.Fatal(err)
	}
	got := time.Since(t1)

	wantLow := bcryptx.GenQuickMaxTime / 2
	wantHigh := bcryptx.GenQuickMaxTime
	if got < wantLow || got > wantHigh {
		t.Errorf(errFmtGotWant, got, wantLow, wantHigh)
	}

	t1 = time.Now()
	if _, err := bcx.GenStrongFromPass(testPass); err != nil {
		t.Fatal(err)
	}
	got = time.Since(t1)

	wantLow = bcryptx.GenStrongMaxTime / 2
	wantHigh = bcryptx.GenStrongMaxTime
	if got < wantLow || got > wantHigh {
		t.Errorf(errFmtGotWant, got, wantLow, wantHigh)
	}
}

func TestCustomTimeSetup(t *testing.T) {
	var tests = []struct {
		qt time.Duration
		st time.Duration
	}{
		{time.Millisecond * 50, time.Millisecond * 200},
		{time.Millisecond * 200, time.Millisecond * 800},
	}

	for _, v := range tests {
		bcxOpts := &bcryptx.Options{
			GenQuickMaxTime:  v.qt,
			GenStrongMaxTime: v.st,
		}

		bcx := bcryptx.New(bcxOpts)
		if err := bcx.Tune(); err != nil {
			t.Fatal(err)
		}

		t1 := time.Now()
		if _, err := bcx.GenQuickFromPass(testPass); err != nil {
			t.Fatal(err)
		}
		got := time.Since(t1)

		wantLow := v.qt / 2
		wantHigh := v.qt
		if got < wantLow || got > wantHigh {
			t.Errorf(errFmtGotWant, got, wantLow, wantHigh)
		}

		t1 = time.Now()
		if _, err := bcx.GenStrongFromPass(testPass); err != nil {
			t.Fatal(err)
		}
		got = time.Since(t1)

		wantLow = v.st / 2
		wantHigh = v.st
		if got < wantLow || got > wantHigh {
			t.Errorf(errFmtGotWant, got, wantLow, wantHigh)
		}
	}
}
