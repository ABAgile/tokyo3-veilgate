package proxy

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/abagile/veilgate/internal/flow"
)

type flushWriteCloser interface {
	io.WriteCloser
	Flush() error
}

type identityStreamWriter struct{ io.Writer }

func (identityStreamWriter) Close() error { return nil }
func (identityStreamWriter) Flush() error { return nil }

func shouldStreamResponse(method string, status int, contentType string) (bool, bool) {
	if method == http.MethodHead || status >= 100 && status <= 199 || status == http.StatusNoContent || status == http.StatusNotModified {
		return false, false
	}
	return streamingResponseType(contentType)
}

func streamingResponseType(contentType string) (bool, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	switch strings.ToLower(mediaType) {
	case "text/event-stream":
		return true, true
	case "application/x-ndjson", "application/ndjson", "application/jsonl", "application/jsonlines":
		return true, false
	default:
		return false, false
	}
}

func streamingDecoder(body io.Reader, encoding string) (io.ReadCloser, bool, error) {
	switch encoding {
	case "identity":
		return io.NopCloser(body), false, nil
	case "gzip":
		reader, err := gzip.NewReader(body)
		if err != nil {
			return nil, false, fmt.Errorf("decode gzip stream: %w", err)
		}
		return reader, false, nil
	case "deflate":
		buffered := bufio.NewReader(body)
		header, err := buffered.Peek(2)
		if err != nil {
			return nil, false, fmt.Errorf("decode deflate stream: %w", err)
		}
		if header[0]&0x0f == 8 && (uint16(header[0])<<8|uint16(header[1]))%31 == 0 {
			reader, err := zlib.NewReader(buffered)
			if err != nil {
				return nil, false, fmt.Errorf("decode deflate stream: %w", err)
			}
			return reader, false, nil
		}
		return flate.NewReader(buffered), true, nil
	case "br":
		return io.NopCloser(brotli.NewReader(body)), false, nil
	case "zstd":
		reader, err := zstd.NewReader(body)
		if err != nil {
			return nil, false, fmt.Errorf("decode zstd stream: %w", err)
		}
		return reader.IOReadCloser(), false, nil
	default:
		return nil, false, fmt.Errorf("unsupported content encoding %q", encoding)
	}
}

func streamingEncoder(output io.Writer, encoding string, rawDeflate bool) (flushWriteCloser, error) {
	switch encoding {
	case "identity":
		return identityStreamWriter{Writer: output}, nil
	case "gzip":
		return gzip.NewWriter(output), nil
	case "deflate":
		if rawDeflate {
			writer, err := flate.NewWriter(output, flate.DefaultCompression)
			if err != nil {
				return nil, fmt.Errorf("encode deflate stream: %w", err)
			}
			return writer, nil
		}
		return zlib.NewWriter(output), nil
	case "br":
		return brotli.NewWriterLevel(output, brotli.DefaultCompression), nil
	case "zstd":
		writer, err := zstd.NewWriter(output)
		if err != nil {
			return nil, fmt.Errorf("encode zstd stream: %w", err)
		}
		return writer, nil
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
}

func readStreamingRecord(reader *bufio.Reader, sse bool, limit int64) ([]byte, error) {
	var record []byte
	for {
		part, err := reader.ReadSlice('\n')
		record = append(record, part...)
		if int64(len(record)) > limit {
			return nil, errCaptureLimit
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if len(record) == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		line := strings.TrimSuffix(strings.TrimSuffix(string(part), "\n"), "\r")
		if !sse || line == "" || errors.Is(err, io.EOF) {
			return record, nil
		}
	}
}

func (h *Handler) prepareStreamingResponse(resp *http.Response, client, host string, item *flow.Flow) (string, bool, error) {
	streaming, sse := streamingResponseType(resp.Header.Get("Content-Type"))
	if !streaming {
		return "", false, errors.New("response is not a supported streaming media type")
	}
	encoding, err := contentEncoding(resp.Header)
	if err != nil {
		return "", false, err
	}
	item.ResponseSecretNames = mergeNames(item.ResponseSecretNames, h.scrubResponseMetadata(resp, client, host))
	var truncated bool
	item.Capture.ResponseHeaders, truncated = captureHeaders(resp.Header, "", h.Secrets, h.captureLimit())
	item.Capture.Truncated = item.Capture.Truncated || truncated
	item.Capture.ResponseBody = &flow.PayloadCapture{
		ContentType: string(sanitizeCaptureBytes(h.Secrets, []byte(resp.Header.Get("Content-Type")), nil)),
	}
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	removeIntegrityHeaders(resp.Header)
	return encoding, sse, nil
}

func (h *Handler) streamResponseBody(resp *http.Response, output io.Writer, flush func() error, encoding string, sse bool, client, host string, item *flow.Flow) (int64, error) {
	var received int64
	counted := &countingReadCloser{ReadCloser: resp.Body, n: &received}
	decoder, rawDeflate, err := streamingDecoder(counted, encoding)
	if err != nil {
		return received, err
	}
	defer decoder.Close()
	encoder, err := streamingEncoder(output, encoding, rawDeflate)
	if err != nil {
		return received, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = encoder.Close()
		}
	}()
	capture := streamCapture{item: item, limit: h.captureLimit(), broker: h.Secrets}
	defer capture.finish()
	reader := bufio.NewReaderSize(decoder, 32*1024)
	for {
		record, readErr := readStreamingRecord(reader, sse, h.mediationLimit())
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return received, fmt.Errorf("read streaming response record: %w", readErr)
		}
		transformed := record
		if h.Secrets != nil {
			var names []string
			transformed, names = h.Secrets.Scrub(record, client, host)
			item.ResponseSecretNames = mergeNames(item.ResponseSecretNames, names)
		}
		capture.add(transformed)
		if _, err := encoder.Write(transformed); err != nil {
			return received, err
		}
		if err := encoder.Flush(); err != nil {
			return received, err
		}
		if flush != nil {
			if err := flush(); err != nil {
				return received, err
			}
		}
	}
	if err := encoder.Close(); err != nil {
		return received, err
	}
	closed = true
	return received, nil
}

type streamCapture struct {
	item   *flow.Flow
	limit  int64
	broker SecretBroker
	text   strings.Builder
}

func (capture *streamCapture) add(transformed []byte) {
	if capture.item.Capture.ResponseBody == nil {
		return
	}
	clean := transformed
	if capture.broker != nil {
		clean = capture.broker.Sanitize(clean)
	}
	remaining := max(capture.limit-int64(capture.text.Len()), 0)
	if int64(len(clean)) > remaining {
		clean = clean[:remaining]
		for len(clean) > 0 && !utf8.Valid(clean) {
			clean = clean[:len(clean)-1]
		}
		capture.item.Capture.Truncated = true
	}
	_, _ = capture.text.Write(clean)
}

func (capture *streamCapture) finish() {
	if capture.item.Capture.ResponseBody != nil {
		capture.item.Capture.ResponseBody.Text = capture.text.String()
	}
}

func writeHTTP1StreamingHead(output io.Writer, resp *http.Response) error {
	removeHopHeaders(resp.Header)
	resp.Header.Del("Content-Length")
	resp.Header.Set("Transfer-Encoding", "chunked")
	if resp.Close {
		resp.Header.Set("Connection", "close")
	}
	if len(resp.Trailer) > 0 {
		for name := range resp.Trailer {
			resp.Header.Add("Trailer", textproto.CanonicalMIMEHeaderKey(name))
		}
	}
	if _, err := fmt.Fprintf(output, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	if err := resp.Header.Write(output); err != nil {
		return err
	}
	_, err := io.WriteString(output, "\r\n")
	return err
}
