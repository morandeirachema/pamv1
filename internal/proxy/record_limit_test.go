package proxy

import (
	"errors"
	"testing"
	"time"
)

// TestRecordingSizeCap proves a recording enforces its byte cap: writes are
// accepted until the cap is reached (the crossing frame is still recorded), then
// Write returns errRecordingLimit so the session is torn down instead of running
// unrecorded.
func TestRecordingSizeCap(t *testing.T) {
	rec, err := newRecording(t.TempDir(), "cap-test", time.Now(), 100) // 100-byte cap
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()

	// A 60-byte write stays under the cap.
	if n, werr := rec.Write(make([]byte, 60)); werr != nil || n != 60 {
		t.Fatalf("first write: n=%d err=%v", n, werr)
	}
	// A second 60-byte write crosses the cap: it is recorded (no error), but the
	// recording is now marked limited.
	if _, werr := rec.Write(make([]byte, 60)); werr != nil {
		t.Fatalf("the crossing write should still be recorded: %v", werr)
	}
	// Any further write is refused with errRecordingLimit.
	if _, werr := rec.Write([]byte("more")); !errors.Is(werr, errRecordingLimit) {
		t.Fatalf("post-cap write: want errRecordingLimit, got %v", werr)
	}
}

// TestRecordingUnlimited confirms maxBytes=0 never caps.
func TestRecordingUnlimited(t *testing.T) {
	rec, err := newRecording(t.TempDir(), "nocap", time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	for i := 0; i < 200; i++ {
		if _, werr := rec.Write(make([]byte, 1024)); werr != nil {
			t.Fatalf("unlimited recording errored at write %d: %v", i, werr)
		}
	}
}
