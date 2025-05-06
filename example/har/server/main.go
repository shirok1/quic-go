package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}

type HAR struct {
	Log struct {
		Entries []struct {
			Request struct {
				URL string `json:"url"`
			} `json:"request"`
			Response struct {
				Content struct {
					File string `json:"_file"`
				} `json:"content"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	addr := flag.String("addr", "localhost:4242", "server address")
	magnify := flag.Uint("magnify", 1, "repeat file transfer")
	cdnlist := flag.String("cdnlist", "", "suffixes will do")
	// harPath := flag.String("har", "har.json", "path to HAR file")
	flag.Parse()
	harPaths := flag.Args()
	if len(harPaths) != 1 {
		log.Fatal("no har file specified")
	}
	harPath := harPaths[0]
	harDir := filepath.Dir(harPath)

	cdns, err := loadSuffixList(*cdnlist)
	if err != nil {
		utils.Infof("cdnlist: %v", err)
	}

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogTimeFormat("")

	listener, err := quic.ListenAddr(*addr, generateTLSConfig(), &quic.Config{CreatePaths: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Listening on", addr)

	har := loadHAR(harPath)

	for {
		sess, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			continue
		}
		go func(sess quic.Session) {
			count := uint64(0)
			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					utils.Infof("accept stream failed: %#v", err)
					// if err == qerr.PeerGoingAway {
					// 	utils.Infof("connection closed, total handled %d/%d", count, len(har.Log.Entries))
					break
					// } else {
					// 	return
					// }
				}
				go handleStream(stream, har, harDir, &count, *magnify, cdns)
			}
			utils.Infof("connection closed, total sent %d/%d", count, len(har.Log.Entries))
		}(sess)
	}
}

func handleStream(stream quic.Stream, har *HAR, harDir string, count *uint64, magnification uint, cdns []string) {
	defer stream.Close()

	// 读取客户端发来的编号
	buf := make([]byte, 8) // uint64 is 8 bytes
	n, err := stream.Read(buf)
	if err != nil {
		log.Fatal(err)
		return
	}
	if n != 8 {
		log.Fatal("invalid number of bytes read")
		return
	}
	index := binary.BigEndian.Uint64(buf)
	if index >= uint64(len(har.Log.Entries)) {
		log.Fatal("invalid index: ", index)
		return
	}
	utils.Infof("client is asking for entry %d", index)

	go func() {
		io.Copy(io.Discard, stream)
	}()

	entry := har.Log.Entries[index]

	u, err := url.Parse(entry.Request.URL)
	if err != nil {
		log.Println("url parse error:", err)
		return
	}

	if hasAnySuffix(u.Host, cdns) {
		stream.SetTag(quic.FlowTagSlot, quic.FlowCDN)
	} else {
		stream.SetTag(quic.FlowTagSlot, quic.FlowAPI)
	}

	// 发送对应 response 文件内容
	filename := entry.Response.Content.File
	if filename != "" {
		file, err := os.Open(filepath.Join(harDir, filename))
		if err != nil {
			log.Fatal(err)
			return
		}
		defer file.Close()
		for range magnification {
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				utils.Errorf("seek to start: %w", err)
			}
			_, err = io.Copy(stream, file)
			if err != nil {
				log.Println("stream copy error:", err)
				return
			}
		}
	}
	utils.Infof("sent response file %s", filename)
	atomic.AddUint64(count, 1)
}

func loadHAR(path string) *HAR {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		log.Fatal(err)
	}
	utils.Infof("loaded %d entries", len(har.Log.Entries))
	return &har
}

func loadSuffixList(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var suffixes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			suffixes = append(suffixes, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return suffixes, nil
}

func hasAnySuffix(s string, suffixes []string) bool {
	if suffixes == nil {
		return false
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}
