package util

import (
	"github.com/rs/zerolog"
	"io/ioutil"
	"os"
	"strconv"
	"time"
)

var (
	lastRead time.Time
	lag      time.Duration
)
var log zerolog.Logger

func TimeDelayHack() time.Duration {
	if lastRead.IsZero() || time.Since(lastRead) >= time.Second*60 {
		lastRead = time.Now()
		fileName := os.Getenv("TIME_DELAY_HACK")
		if fileName != "" {
			data, err := ioutil.ReadFile(fileName)
			if err != nil {
				log.Warn().Err(err)
				return 0
			}
			number, err := strconv.Atoi(string(data))
			if err != nil {
				log.Warn().Err(err)
				return 0
			}
			lag = time.Duration(number) * time.Millisecond
		}
	}
	return lag
}
