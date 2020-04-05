package util

import (
	"math/rand"
	"time"
)

// Retry attempts a function `attempts` number of times. It exponentially
// backs off the initial `sleep` upon failures.
// Credit to Nick Stogner from a May 2017 post.
func Retry(attempts int, sleep time.Duration, f func() error) error {
	if err := f(); err != nil {
		if s, ok := err.(RetryStop); ok {
			return s
		}

		if attempts--; attempts > 0 {
			// Add some randomness to prevent creating a Thundering Herd
			jitter := time.Duration(rand.Int63n(int64(sleep)))
			sleep = sleep + jitter/2

			time.Sleep(sleep)
			return Retry(attempts, 2*sleep, f)
		}
		return err
	}
	return nil
}

// RetryStop : return this error from your Retry-ing function to abort
// future attempts.
type RetryStop struct {
	Err error
}

func (stop RetryStop) Error() string {
	return stop.Err.Error()
}
