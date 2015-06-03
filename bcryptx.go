// Package bcryptx ....
package bcryptx

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// GenQuickMaxTime is the default max time used for tuning Bcrypter.quickCost.
	GenQuickMaxTime = time.Millisecond * 500
	// GenStrongMaxTime is the default max time used for tuning Bcrypter.strongCost.
	GenStrongMaxTime = time.Millisecond * 2000
	// GenConcurrency is the default concurrency value used for Gen*FromPass.
	GenConcurrency = 2

	minCost    = bcrypt.MinCost
	maxCost    = bcrypt.MaxCost
	interpTime = time.Millisecond * 50
	testStr    = "#!PnutBudr"
)

var (
	// ErrLowCost is returned by failed IsCost* functions.
	ErrLowCost = errors.New("Hash cost lower than currently configured cost.")
)

// Options holds values to be passed to New.
type Options struct {
	GenQuickMaxTime  time.Duration
	GenStrongMaxTime time.Duration
	GenConcurrency   int
}

// Bcrypter holds
type Bcrypter struct {
	mu         *sync.RWMutex
	tuningWg   *sync.WaitGroup
	Options    *Options
	quickCost  int
	strongCost int
	concCount  chan bool
}

// New returns a *Bcrypter based on Options values or defaults.
func New(opts *Options) *Bcrypter {
	if opts == nil {
		opts = &Options{}
	}

	if opts.GenQuickMaxTime == 0 {
		opts.GenQuickMaxTime = GenQuickMaxTime
	}
	if opts.GenStrongMaxTime == 0 {
		opts.GenStrongMaxTime = GenStrongMaxTime
	}

	if opts.GenConcurrency == 0 {
		opts.GenConcurrency = GenConcurrency
	}

	return &Bcrypter{
		Options: opts, mu: &sync.RWMutex{}, tuningWg: &sync.WaitGroup{},
		concCount: make(chan bool, opts.GenConcurrency),
	}
}

// GenQuickFromPass returns a hash produced using Bcrypter.quickCost.
func (bc *Bcrypter) GenQuickFromPass(pass string) (string, error) {
	bc.concCount <- true
	defer func() { <-bc.concCount }()
	c := bc.CurrentQuickCost()
	b, err := bcrypt.GenerateFromPassword([]byte(pass), c)
	return string(b), err
}

// GenStrongFromPass returns a hash produced using Bcrypter.strongCost.
func (bc *Bcrypter) GenStrongFromPass(pass string) (string, error) {
	bc.concCount <- true
	defer func() { <-bc.concCount }()
	c := bc.CurrentStrongCost()
	b, err := bcrypt.GenerateFromPassword([]byte(pass), c)
	return string(b), err
}

// CompareHashAndPass receives a hashed password and password strings, and returns an
// error if comparison fails.
func (bc *Bcrypter) CompareHashAndPass(hash, pass string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
}

// Tune wraps tune so that Bcrypter.tuningWg is surely used.
func (bc *Bcrypter) Tune() {
	bc.tuningWg.Wait()
	bc.tuningWg.Add(1)
	bc.tune(bc.tuningWg)
}

// IsCostQuick returns the results of testHash with Bcrypter.quickCost.
func (bc *Bcrypter) IsCostQuick(hash string) error {
	c := bc.CurrentQuickCost()
	return testHash(hash, c)
}

// IsCostStrong returns the results of testHash with Bcrypter.strongCost.
func (bc *Bcrypter) IsCostStrong(hash string) error {
	c := bc.CurrentStrongCost()
	return testHash(hash, c)
}

func (bc *Bcrypter) CurrentQuickCost() int {
	bc.tuningWg.Wait()
	bc.mu.RLock()
	c := bc.quickCost
	bc.mu.RUnlock()

	if c == 0 {
		bc.Tune()
		bc.mu.RLock()
		c = bc.quickCost
		bc.mu.RUnlock()
	}
	return c
}

func (bc *Bcrypter) CurrentStrongCost() int {
	bc.tuningWg.Wait()
	bc.mu.RLock()
	c := bc.strongCost
	bc.mu.RUnlock()

	if c == 0 {
		bc.Tune()
		bc.mu.RLock()
		c = bc.strongCost
		bc.mu.RUnlock()
	}
	return c
}

// tune returns any test hash processing errors.
func (bc *Bcrypter) tune(wg *sync.WaitGroup) {
	defer wg.Done()
	var qc, sc int

	cts := []time.Duration{0}
	for i := 1; i <= maxCost; i++ {
		if i < minCost {
			cts = append(cts, 0)
			continue
		}

		if cts[i-1] < interpTime {
			t1 := time.Now()
			_, err := bcrypt.GenerateFromPassword([]byte(testStr), i)
			d := time.Since(t1)
			if err != nil {
				panic("Failed to tune bcryptx: " + err.Error())
			}

			cts = append(cts, d)
			continue
		}

		tct := cts[i-1] * 2
		tct = tct - (tct % (time.Millisecond * 10))
		cts = append(cts, tct)
	}

	for k := range cts {
		if qc == 0 && len(cts) > k+1 && cts[k+1] > bc.Options.GenQuickMaxTime {
			qc = k
		}
		if sc == 0 && len(cts) > k+1 && cts[k+1] > bc.Options.GenStrongMaxTime {
			sc = k
		}
	}

	bc.mu.Lock()
	bc.quickCost = qc
	bc.strongCost = sc
	bc.mu.Unlock()
}

// test returns an error if the apparent cost of the hash is lower than the
// provided cost, or if any errors are encountered during hash analysis.
func testHash(hash string, cost int) error {
	c, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return err
	}
	if c < cost {
		return ErrLowCost
	}
	return nil
}
