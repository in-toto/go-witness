package timestamp

import (
	"context"
	"fmt"
	"io"
	"time"
)

type FakeTimestamper struct {
	T time.Time
}

func (ft FakeTimestamper) Timestamp(context.Context, io.Reader) ([]byte, error) {
	return []byte(ft.T.Format(time.RFC3339)), nil
}

func (ft FakeTimestamper) Verify(ctx context.Context, ts io.Reader, sig io.Reader) (time.Time, error) {
	b, err := io.ReadAll(ts)
	if err != nil {
		return time.Time{}, err
	}

	if string(b) != ft.T.Format(time.RFC3339) {
		return time.Time{}, fmt.Errorf("mismatched time")
	}

	return ft.T, nil
}
