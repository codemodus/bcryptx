# bcryptx

    go get "github.com/codemodus/bcryptx"

Package bcryptx automates the tuning of bcrypt costs based on an environment's 
available processing resources.  Concurrency throttling is provided, as well 
as convenience functions for making use of tuned costs with bcrypt functions.

quickCost should be used when a hash should be accessible quickly.  strongCost 
should be used when the delay of processing can be mitigated.

## Usage

```go
type Bcrypter
    func New(opts *Options) *Bcrypter
    func (bc *Bcrypter) CompareHashAndPass(hash, pass string) error
    func (bc *Bcrypter) CurrentQuickCost() (int, error)
    func (bc *Bcrypter) CurrentStrongCost() (int, error)
    func (bc *Bcrypter) GenQuickFromPass(pass string) (string, error)
    func (bc *Bcrypter) GenStrongFromPass(pass string) (string, error)
    func (bc *Bcrypter) IsCostQuick(hash string) bool
    func (bc *Bcrypter) IsCostStrong(hash string) bool
    func (bc *Bcrypter) Tune() error
    func (bc *Bcrypter) ValidateHash(hash string) error
type Options
```

### Setup

```go
import (
    "github.com/codemodus/bcryptx"
)

func main() {
    // ...

    bcxOpts := &bcryptx.Options{
        GenQuickMaxTime:  time.Millisecond * 400, // default is 500ms
        GenStrongMaxTime: time.Millisecond * 1600, // default is 2000ms
        GenConcurrency:   1, // default is 2
    }

    // To use defaults, provide nil instead of a bcryptx.Options object.
    bcx := bcryptx.New(bcxOpts)
	if err := bcx.Tune(); err != nil {
		// ...
	}

    hash, err := bcx.GenQuickFromPass("12345")
    if err != nil {
        // ...
    }

    // ...
}
```

### Beyond Setup
```go
func main() {
    // ...
    
    if err := bcx.CompareHashAndPass(hash, "spaceballs"); err != nil {
        // Generated hash for "12345", tested for "spaceballs".
    }

    if ok := bcx.IsCostStrong(hash); !ok {
        // Hashed quick, wanted strong.
    }
    
    // ...
}
```

## More Info

### Notes On Tuning

The tuning algorithm produces a handful of low-cost hashes and uses the 
resulting durations to interpolate the durations of hashes with higher costs.  
It is preferable to tune during times of normal resource consumption.  While it 
is reasonable to run Tune in a goroutine, be mindful of concurrent processing 
burdens.  With some basic consideration, tuning will produce satisfactory 
results which grow in security along with provisioned resources.  Also worth 
noting is that interpolated hash durations are quantized to the nearest 
hundreth of a second.

## Documentation

View the [GoDoc](http://godoc.org/github.com/codemodus/bcryptx)

## Benchmarks

N/A
