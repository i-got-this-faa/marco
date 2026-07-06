package blobstore

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// compile-time check that *S3Store implements Store.
var _ Store = (*S3Store)(nil)

// fakeS3Client returns a minimal *s3.Client suitable for tests that do not
// make actual S3 API calls (no real credentials or network needed).
func fakeS3Client() *s3.Client {
	return s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("fake", "fake", ""),
		BaseEndpoint: aws.String("http://localhost:9000"),
		UsePathStyle: true,
	})
}

func TestNewS3Store(t *testing.T) {
	s, err := NewS3Store(
		context.Background(),
		"test-bucket",
		"prefix/",
		"http://localhost:9000",
		"us-east-1",
		WithS3Client(fakeS3Client()),
	)
	if err != nil {
		t.Fatalf("NewS3Store failed: %v", err)
	}
	if s == nil {
		t.Fatal("NewS3Store returned nil")
	}
	if s.bucket != "test-bucket" {
		t.Errorf("bucket = %q, want %q", s.bucket, "test-bucket")
	}
	if s.prefix != "prefix/" {
		t.Errorf("prefix = %q, want %q", s.prefix, "prefix/")
	}
}

func TestS3StoreCapabilities(t *testing.T) {
	s, err := NewS3Store(
		context.Background(),
		"b", "", "", "us-east-1",
		WithS3Client(fakeS3Client()),
	)
	if err != nil {
		t.Fatalf("NewS3Store failed: %v", err)
	}
	c := s.Capabilities()
	if !c.Streaming {
		t.Error("S3Store should support streaming")
	}
	if !c.RangeRead {
		t.Error("S3Store should support range read")
	}
	if !c.Checksums {
		t.Error("S3Store should support checksums")
	}
}

func TestS3StoreCompileTimeInterface(t *testing.T) {
	// This test is redundant with the var_ check at package level but
	// verifies the package-level assertion is actually compiled.
	s, err := NewS3Store(
		context.Background(),
		"b", "", "", "us-east-1",
		WithS3Client(fakeS3Client()),
	)
	if err != nil {
		t.Fatalf("NewS3Store failed: %v", err)
	}
	// If it compiles and runs, *S3Store implements Store.
	var store Store = s
	if store == nil {
		t.Fatal("store is nil")
	}
}

func TestS3StoreWithS3ClientOption(t *testing.T) {
	client := fakeS3Client()
	s, err := NewS3Store(
		context.Background(),
		"bucket", "", "", "us-east-1",
		WithS3Client(client),
	)
	if err != nil {
		t.Fatalf("NewS3Store with client option failed: %v", err)
	}
	if s.client != client {
		t.Error("WithS3Client did not set the expected client")
	}
}

// TestS3StorePutFailsWithFakeClient verifies that Put returns an error
// when called with a fake (non-functional) client, confirming the code
// path is exercised without needing a real S3 endpoint.
func TestS3StorePutFailsWithFakeClient(t *testing.T) {
	s, err := NewS3Store(
		context.Background(),
		"b", "", "", "us-east-1",
		WithS3Client(fakeS3Client()),
	)
	if err != nil {
		t.Fatalf("NewS3Store failed: %v", err)
	}
	_, _, err = s.Put(context.Background(), strings.NewReader("data"), nil)
	if err == nil {
		t.Skip("S3 Put unexpectedly succeeded (real endpoint reachable?)")
	}
	if !strings.Contains(err.Error(), "blobstore: s3 put:") {
		t.Errorf("error does not wrap blobstore prefix: %v", err)
	}
}

// TestS3StoreGetFailsWithFakeClient verifies that Get returns an error
// with a non-functional client.
func TestS3StoreGetFailsWithFakeClient(t *testing.T) {
	s, err := NewS3Store(
		context.Background(),
		"b", "", "", "us-east-1",
		WithS3Client(fakeS3Client()),
	)
	if err != nil {
		t.Fatalf("NewS3Store failed: %v", err)
	}
	_, err = s.Get(context.Background(), "some-key")
	if err == nil {
		t.Skip("S3 Get unexpectedly succeeded (real endpoint reachable?)")
	}
}

// TestS3StoreDeleteWithFakeClient verifies Delete code path.
func TestS3StoreDeleteWithFakeClient(t *testing.T) {
	s, err := NewS3Store(
		context.Background(),
		"b", "", "", "us-east-1",
		WithS3Client(fakeS3Client()),
	)
	if err != nil {
		t.Fatalf("NewS3Store failed: %v", err)
	}
	err = s.Delete(context.Background(), "some-key")
	if err == nil {
		t.Skip("S3 Delete unexpectedly succeeded (real endpoint reachable?)")
	}
}

// TestS3StoreExistsWithFakeClient verifies Exists code path.
func TestS3StoreExistsWithFakeClient(t *testing.T) {
	s, err := NewS3Store(
		context.Background(),
		"b", "", "", "us-east-1",
		WithS3Client(fakeS3Client()),
	)
	if err != nil {
		t.Fatalf("NewS3Store failed: %v", err)
	}
	_, err = s.Exists(context.Background(), "some-key")
	if err == nil {
		t.Skip("S3 Exists unexpectedly succeeded (real endpoint reachable?)")
	}
}

// Ensure the countingReader helper correctly tracks bytes read.
func TestCountingReader(t *testing.T) {
	input := "hello world"
	cr := &countingReader{r: strings.NewReader(input)}
	data, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(data) != input {
		t.Errorf("content = %q, want %q", string(data), input)
	}
	if cr.count != int64(len(input)) {
		t.Errorf("count = %d, want %d", cr.count, len(input))
	}
}
