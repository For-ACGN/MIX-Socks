package msocks

import (
	"compress/flate"
	"compress/gzip"
	"net/http"
	"os"
)

func isDir(path string) bool {
	file, err := os.Open(path) // #nosec
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return stat.IsDir()
}

type gzipResponseWriter struct {
	http.ResponseWriter
	w *gzip.Writer

	written bool
	enabled bool
}

func (rw *gzipResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.enabled = rw.Header().Get("Content-Encoding") == "gzip"
		rw.written = true
	}
	if rw.enabled {
		return rw.w.Write(b)
	}
	return rw.ResponseWriter.Write(b)
}

type flateResponseWriter struct {
	http.ResponseWriter
	w *flate.Writer

	written bool
	enabled bool
}

func (rw *flateResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.enabled = rw.Header().Get("Content-Encoding") == "deflate"
		rw.written = true
	}
	if rw.enabled {
		return rw.w.Write(b)
	}
	return rw.ResponseWriter.Write(b)
}
