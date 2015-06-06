// Package bcryptx automates the tuning of bcrypt costs based on an
// environment's available processing resources.  Concurrency throttling is
// provided, as well as convenience functions for making use of tuned costs
// with bcrypt functions.
//
// quickCost should be used when a hash should be accessible quickly.
// strongCost should be used when the delay of processing can be mitigated.
package bcryptx

import (
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// GenQuickMaxTime is the default max time used for tuning
	// Bcrypter.quickCost.
	GenQuickMaxTime = time.Millisecond * 500

	// GenStrongMaxTime is the default max time used for tuning
	// Bcrypter.strongCost.
	GenStrongMaxTime = time.Millisecond * 2000

	// GenConcurrency is the default goroutine count used for Gen*FromPass.
	GenConcurrency = 2

	minCost    = bcrypt.MinCost
	maxCost    = bcrypt.MaxCost
	interpTime = time.Millisecond * 50
	testStr    = "#!PnutBudr"
)

// Options holds values to be passed to New.
type Options struct {
	// GenQuickMaxTime is the max time used for tuning Bcrypter.quickCost.
	GenQuickMaxTime  time.Duration

	// GenStrongMaxTime is the max time used for tuning Bcrypter.strongCost.
	GenStrongMaxTime time.Duration

	// GenConcurrency is the goroutine count used for Gen*FromPass.
	GenConcurrency   int
}

// Bcrypter provides an API for bcrypt functions with "quick" or "strong" costs.
// Tune is called on first use of Gen*FromPass if not already called directly.
type Bcrypter struct {
	mu         *sync.RWMutex
	tuningWg   *sync.WaitGroup
	options    *Options
	quickCost  int
	strongCost int
	concCount  chan bool
}

// New returns a new Bcrypter based on Options values or defaults.
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
		options: opts, mu: &sync.RWMutex{}, tuningWg: &sync.WaitGroup{},
		concCount: make(chan bool, opts.GenConcurrency),
	}
}

// GenQuickFromPass returns a hash produced using Bcrypter.quickCost or any
// error encountered during handling.
func (bc *Bcrypter) GenQuickFromPass(pass string) (string, error) {
	bc.concCount <- true
	defer func() { <-bc.concCount }()
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bc.CurrentQuickCost())
	return string(b), err
}

// GenStrongFromPass returns a hash produced using Bcrypter.strongCost or any
// error encountered during handling.
func (bc *Bcrypter) GenStrongFromPass(pass string) (string, error) {
	bc.concCount <- true
	defer func() { <-bc.concCount }()
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bc.CurrentStrongCost())
	return string(b), err
}

// CompareHashAndPass returns an error if comparison fails or any error
// encountered during handling.
func (bc *Bcrypter) CompareHashAndPass(hash, pass string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
}

// Tune sets the quick and strong costs based on provided max times.
// Appropriate costs are determined by producing a handful of low-cost hashes,
// then using the resulting durations to interpolate the durations of hashes
// with higher costs.
func (bc *Bcrypter) Tune() {
	bc.tuningWg.Wait()
	bc.tuningWg.Add(1)
	bc.tune(bc.tuningWg)
}

// IsCostQuick returns false if the apparent cost of the hash is lower than
// the provided cost, or if any errors are encountered during hash analysis.
func (bc *Bcrypter) IsCostQuick(hash string) bool {
	return testHash(hash, bc.CurrentQuickCost())
}

// IsCostStrong returns false if the apparent cost of the hash is lower than
// the provided cost, or if any errors are encountered during hash analysis.
func (bc *Bcrypter) IsCostStrong(hash string) bool {
	return testHash(hash, bc.CurrentStrongCost())
}

// CurrentQuickCost returns the quickCost as set by Tune.
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

// CurrentStrongCost returns the strongCost as set by Tune.
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

// tune sets Bcrypter.quickCost and Bcrypter.strongCost, and panics on any
// error or if any cost is unable to be determined.
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
		if qc == 0 && len(cts) > k+1 && cts[k+1] > bc.options.GenQuickMaxTime {
			qc = k
		}
		if sc == 0 && len(cts) > k+1 && cts[k+1] > bc.options.GenStrongMaxTime {
			sc = k
		}
	}

	if qc == 0 || sc == 0 {
		panic("bcrypt hash times are too low.")
	}

	bc.mu.Lock()
	bc.quickCost = qc
	bc.strongCost = sc
	bc.mu.Unlock()
}

// test returns false if the apparent cost of the hash is lower than the
// provided cost, or if any errors are encountered during hash analysis.
func testHash(hash string, cost int) bool {
	c, err := bcrypt.Cost([]byte(hash))
	if err != nil || c < cost {
		return false
	}
	return true
}
