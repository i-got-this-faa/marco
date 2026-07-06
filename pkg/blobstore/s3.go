package blobstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// S3Store stores blobs in an S3-compatible object store.
type S3Store struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewS3Store creates an S3Store backed by an S3-compatible object store.
// It uses the default AWS credential chain (env vars, ~/.aws/credentials, etc.).
//
// When endpoint is non-empty, it sets a custom base endpoint (for MinIO
// and other S3-compatible services) and enables path-style addressing.
// A pre-built *s3.Client can be injected via the WithS3Client option to
// bypass the default credential chain.
func NewS3Store(ctx context.Context, bucket, prefix, endpoint, region string, opts ...func(*S3Store)) (*S3Store, error) {
	s := &S3Store{
		bucket: bucket,
		prefix: prefix,
	}

	// Apply options first so a pre-built client can be injected before the
	// default credential chain is invoked.
	for _, opt := range opts {
		opt(s)
	}

	if s.client == nil {
		loadOpts := []func(*awsconfig.LoadOptions) error{
			awsconfig.WithRegion(region),
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
		if err != nil {
			return nil, fmt.Errorf("blobstore: aws config: %w", err)
		}

		s.client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			if endpoint != "" {
				o.BaseEndpoint = aws.String(endpoint)
				o.UsePathStyle = true
			}
		})
	}

	return s, nil
}

// WithS3Client is a functional option that replaces the S3 client used by
// the store. Useful in tests or when custom client configuration is needed.
func WithS3Client(client *s3.Client) func(*S3Store) {
	return func(s *S3Store) {
		s.client = client
	}
}

// countingReader wraps an io.Reader and counts bytes read so that the
// total uploaded size can be reported without buffering.
type countingReader struct {
	r     io.Reader
	count int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.count += int64(n)
	return n, err
}

func (s *S3Store) objectKey(key string) string {
	return s.prefix + key
}

// Put uploads a blob to S3 using the SHA-256 digest as the key, providing
// content-addressed dedup. Returns the hex digest key, number of bytes
// written, and any error encountered.
func (s *S3Store) Put(ctx context.Context, r io.Reader, metadata map[string]string) (string, int64, error) {
	key, data, size, err := sha256Key(r)
	if err != nil {
		return "", 0, err
	}

	// Check existence — quick dedup.
	exists, err := s.Exists(ctx, key)
	if err == nil && exists {
		return key, size, nil
	}

	input := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s.objectKey(key)),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(size),
	}
	if len(metadata) > 0 {
		input.Metadata = metadata
	}
	if _, err := s.client.PutObject(ctx, input); err != nil {
		return "", 0, fmt.Errorf("blobstore: s3 put: %w", err)
	}
	return key, size, nil
}

// Get returns a reader for the blob identified by key. The caller MUST
// close the returned io.ReadCloser to release resources.
func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, fmt.Errorf("blobstore: not found: %w", err)
		}
		return nil, fmt.Errorf("blobstore: s3 get: %w", err)
	}
	return output.Body, nil
}

// Delete removes a blob from S3. Deleting a non-existent blob is not an
// error (S3 DeleteObject is idempotent).
func (s *S3Store) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	})
	if err != nil {
		return fmt.Errorf("blobstore: s3 delete: %w", err)
	}
	return nil
}

// Exists checks whether a blob with the given key exists in S3.
func (s *S3Store) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	})
	if err == nil {
		return true, nil
	}

	// HeadObject returns a 404 when the object does not exist.
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) && re.Response.StatusCode == http.StatusNotFound {
		return false, nil
	}

	// Also check NoSuchKey (returned by other S3 operations, included for
	// completeness).
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return false, nil
	}

	return false, fmt.Errorf("blobstore: s3 head: %w", err)
}

// Capabilities returns the store's capabilities.
func (s *S3Store) Capabilities() Capabilities {
	return Capabilities{
		Streaming: true,
		RangeRead: true,
		Checksums: true,
	}
}
