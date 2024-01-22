package timestamp

import (
	"context"
	"io"
	"time"
)

type TimestampVerifier interface {
	Verify(context.Context, io.Reader, io.Reader) (time.Time, error)
}

type Timestamper interface {
	Timestamp(context.Context, io.Reader) ([]byte, error)
}
