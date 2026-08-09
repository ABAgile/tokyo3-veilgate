package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func contentEncoding(header http.Header) (string, error) {
	value := strings.ToLower(strings.TrimSpace(strings.Join(header.Values("Content-Encoding"), ",")))
	if value == "" || value == "identity" {
		return "identity", nil
	}
	if strings.Contains(value, ",") {
		return "", errors.New("stacked content encodings are not supported")
	}
	switch value {
	case "gzip", "deflate", "br", "zstd":
		return value, nil
	default:
		return "", fmt.Errorf("unsupported content encoding %q", value)
	}
}

func decodeHTTPBody(data []byte, encoding string, limit int64) ([]byte, error) {
	var reader io.ReadCloser
	switch encoding {
	case "identity":
		return append([]byte(nil), data...), nil
	case "gzip":
		gzipReader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decode gzip body: %w", err)
		}
		reader = gzipReader
	case "deflate":
		zlibReader, err := zlib.NewReader(bytes.NewReader(data))
		if err == nil {
			reader = zlibReader
		} else {
			reader = flate.NewReader(bytes.NewReader(data))
		}
	case "br":
		reader = io.NopCloser(brotli.NewReader(bytes.NewReader(data)))
	case "zstd":
		zstdReader, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decode zstd body: %w", err)
		}
		reader = zstdReader.IOReadCloser()
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
	defer reader.Close()
	decoded, err := readBounded(reader, limit)
	if err != nil {
		if errors.Is(err, errCaptureLimit) {
			return nil, errors.New("decoded body exceeds capture limit")
		}
		return nil, fmt.Errorf("decode %s body: %w", encoding, err)
	}
	return decoded, nil
}

func encodeHTTPBody(data []byte, encoding string, limit int64) ([]byte, error) {
	if encoding == "identity" {
		return append([]byte(nil), data...), nil
	}
	var output bytes.Buffer
	var writer io.WriteCloser
	switch encoding {
	case "gzip":
		writer = gzip.NewWriter(&output)
	case "deflate":
		writer = zlib.NewWriter(&output)
	case "br":
		writer = brotli.NewWriterLevel(&output, brotli.DefaultCompression)
	case "zstd":
		zstdWriter, err := zstd.NewWriter(&output)
		if err != nil {
			return nil, fmt.Errorf("encode zstd body: %w", err)
		}
		writer = zstdWriter
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("encode %s body: %w", encoding, err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("encode %s body: %w", encoding, err)
	}
	if int64(output.Len()) > limit {
		return nil, errors.New("encoded body exceeds capture limit")
	}
	return output.Bytes(), nil
}

func removeIntegrityHeaders(header http.Header) {
	for _, name := range []string{"Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "Signature", "Signature-Input"} {
		header.Del(name)
	}
}
