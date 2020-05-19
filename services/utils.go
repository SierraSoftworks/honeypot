package services

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode"

	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
)

func getIPAddress(addr net.Addr) string {
	parts := strings.Split(addr.String(), ":")

	return strings.Join(parts[:len(parts)-1], ":")
}

func getIPAddressFromString(addr string) string {
	parts := strings.Split(addr, ":")

	return strings.Join(parts[:len(parts)-1], ":")
}

func isText(s string) bool {
	for _, c := range s {
		if c > unicode.MaxLatin1 || c < 0x20 {
			return false
		}
	}

	return true
}

func capturePayload(r io.Reader, m *honeypot.Metadata) (int64, error) {
	hash := md5.New()
	buf := new(bytes.Buffer)

	n, err := io.Copy(hash, io.TeeReader(r, LimitWriter(buf, 128)))

	if n > 0 {
		m.Resources = append(m.Resources, fmt.Sprintf("md5:%x", hash.Sum([]byte{})))

		if isText(buf.String()) {
			m.Resources = append(m.Resources, fmt.Sprintf("%s...", strings.TrimSpace(buf.String())))
		}
	}

	return n, err
}

type limitedWriter struct {
	w io.Writer
	n int64
}

func LimitWriter(w io.Writer, n int64) io.Writer {
	return &limitedWriter{
		w,
		n,
	}
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if w.n == 0 {
		return len(data), nil
	}

	nn, err := w.w.Write(data[:w.n])
	w.n -= int64(nn)

	return nn, err
}
