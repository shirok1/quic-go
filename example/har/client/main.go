package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func generateTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"har-quic"},
	}
}

type HAR struct {
	Log struct {
		Entries []struct {
			Request struct {
				URL      string `json:"url"`
				PostData struct {
					File string `json:"_file"`
				} `json:"postData"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	addr := flag.String("addr", "localhost:4242", "server address")
	magnify := flag.Uint("magnify", 1, "repeat file transfer")
	semsize := flag.Int("sem", 16, "cocurrent limit")
	cdnlist := flag.String("cdnlist", "", "suffixes will do")
	delay := flag.Int64("delay", 5, "before next go func")
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

	session, err := quic.DialAddr(*addr, generateTLSConfig(), &quic.Config{CreatePaths: true})
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close(nil)

	har := loadHAR(harPath)

	sem := make(chan struct{}, *semsize) // 模拟信号量
	var wg sync.WaitGroup
	for idx, entry := range har.Log.Entries {
		utils.Infof("client is asking for entry %d", idx)
		<-time.After(time.Millisecond * time.Duration(*delay))
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, filename string) {
			defer wg.Done()
			defer func() { <-sem }()
			stream, err := session.OpenStream()
			if err != nil {
				log.Println("stream error:", err)
				return
			}
			defer stream.Close()

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

			// 发送编号
			var num uint64 = uint64(i)
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, num)
			_, _ = stream.Write(buf)
			utils.Infof("client is asking for entry %d", i)

			if filename != "" {
				// 再发送请求文件内容
				file, err := os.Open(filepath.Join(harDir, filename))
				if err != nil {
					log.Println("postdata file error:", err)
					return
				}
				defer file.Close()
				for range *magnify {
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

			// 丢弃服务器响应
			io.Copy(io.Discard, stream)
		}(idx, entry.Request.PostData.File)
	}

	wg.Wait()
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
	fmt.Println(har.Log.Entries)
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
