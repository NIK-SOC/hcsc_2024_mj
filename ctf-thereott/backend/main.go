package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var mp4Files []string

const (
	hmacKey  = "K7Sx5Io4gYXH4yQTTv25P7NQA9nQnuSq7ifXUiRf"
	clientId = "hu.honeylab.hcsc.thereott"
	version  = "1.0"
	flag     = "HCSC24{3v3n_n@t1v3s_c4n_b3_h00k3d}"
)

func generateHMACSHA1Signature(key, data string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func md5Hash(data string) string {
	hash := md5.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

func generateSignature(method, path, responseContent, clientId, version, headers, timestamp, body string) string {
	signature := method + "\n" + path + "\n" + responseContent + "\n" + version + "\n" + clientId + "\n" + md5Hash(headers) + "\n" + timestamp + "\n" + md5Hash(body)
	return generateHMACSHA1Signature(hmacKey, signature)
}

func ShowErrorPage(w http.ResponseWriter, reason string, status int) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/html")
	errorPage := GenerateErrorPage(reason)
	w.Write([]byte(errorPage))
}

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method + " " + r.URL.Path + " from " + r.RemoteAddr)
		next(w, r)
	}
}

func validateRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get("X-Signature")
		if signature == "" {
			ShowErrorPage(w, "Missing signature", http.StatusBadRequest)
			return
		}
		timestamp := r.Header.Get("X-Timestamp")
		if timestamp == "" {
			ShowErrorPage(w, "Missing timestamp", http.StatusBadRequest)
			return
		}
		appId := r.Header.Get("X-Tott-App-Id")
		if appId != clientId {
			ShowErrorPage(w, "Invalid x-tott-app-id", http.StatusBadRequest)
			return
		}
		appName := r.Header.Get("X-Tott-App-Name")
		if appName != "ThereOtt" {
			ShowErrorPage(w, "Invalid x-tott-app-name", http.StatusBadRequest)
			return
		}
		var keys []string
		for key := range r.Header {
			keyLower := strings.ToLower(key)
			if len(keyLower) > 7 && keyLower[:7] == "x-tott-" {
				keys = append(keys, keyLower)
			}
		}

		sort.Strings(keys)

		var headers string
		for _, key := range keys {
			value := strings.ToLower(r.Header.Get(key))
			headers += key + ":" + value + ","
		}

		if len(headers) == 0 {
			ShowErrorPage(w, "Missing x-tott headers", http.StatusBadRequest)
			return
		}

		headers = headers[:len(headers)-1]
		body := ""
		if r.Method == "POST" {
			buf := new(strings.Builder)
			_, err := io.Copy(buf, r.Body)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			body = buf.String()

			r.Body = io.NopCloser(strings.NewReader(body))
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Println("Failed to get IP: " + err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		signature = generateSignature(r.Method, r.URL.Path, "", clientId, version, headers, timestamp, body)
		if signature != r.Header.Get("X-Signature") {
			log.Println("Got: " + r.Header.Get("X-Signature") + " Expected: " + signature + " from " + ip)
			ShowErrorPage(w, "Invalid signature", http.StatusBadRequest)
			return
		}
		log.Println("Valid request from " + ip)
		next(w, r)
	}
}

func init() {
	files, err := os.ReadDir("assets")
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".mp4" {
			mp4Files = append(mp4Files, file.Name())
		}
	}

	if len(mp4Files) == 0 {
		panic("No MP4 files found in the assets folder")
	}
}

func getVideo(w http.ResponseWriter, r *http.Request) {
	randomIndex := rand.Intn(len(mp4Files))
	randomMP4 := mp4Files[randomIndex]

	w.Header().Set("Content-Type", "text/plain")

	hostname := r.Host
	if hostname == "" {
		hostname = "localhost:8080"
	}
	prefix := "http://"
	if r.TLS != nil {
		prefix = "https://"
	}
	w.Write([]byte(prefix + hostname + "/assets/" + randomMP4))
}

func getFlag(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Almost! :) But be sure to post \"flag\" to this endpoint", http.StatusMethodNotAllowed)
		return
	}
	buf := new(strings.Builder)
	_, err := io.Copy(buf, r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if buf.String() != "flag" {
		http.Error(w, "Almost! :) But be sure to post \"flag\" to this endpoint", http.StatusMethodNotAllowed)
		return
	}
	go sendDiscordWebhook(r.RemoteAddr, fmt.Sprintf("```%s```", formatHeaders(r.Header)))
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(flag))
}

func main() {
	http.HandleFunc("/api/video.mp4", logRequest(validateRequest(getVideo)))
	http.HandleFunc("/flag", logRequest(validateRequest(getFlag)))
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
	http.HandleFunc("/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "No Content", http.StatusNoContent)
	}))

	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("Listening on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
