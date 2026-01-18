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
}

func (rw *gzipResponseWriter) Write(b []byte) (int, error) {
	return rw.w.Write(b)
}

type flateResponseWriter struct {
	http.ResponseWriter
	w *flate.Writer
}

func (rw *flateResponseWriter) Write(b []byte) (int, error) {
	return rw.w.Write(b)
}
