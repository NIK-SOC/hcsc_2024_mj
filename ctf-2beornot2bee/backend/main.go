package main

import (
	"crypto/aes"
	"crypto/cipher"
	crrand "crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Bee struct {
	File       string `json:"file"`
	Subspecies string `json:"subspecies"`
}

type BeeImage map[string]string

var possibleSubspecies = []string{
	"Carniolan honey bee",
	"Italian honey bee",
	"Russian honey bee",
	"VSH Italian honey bee",
	"Western honey bee",
}

var secretKey []byte
var bees []Bee
var imageFolder = "bee_imgs/"

const flag = "HCSC24{d1d_y0u_f1nd_th3_d4t4s3t_4nd_h4shed_or_d1d_u_use_ml?}"
const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Bee Image Classification</title>
	<style>
		body {
			font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			margin: 0;
			padding: 0;
			background-color: #f8f9fa;
		}
		.container {
			max-width: 800px;
			margin: 0 auto;
			padding: 20px;
			text-align: center;
		}
		h1 {
			text-align: center;
			margin-top: 30px;
			color: #3e3e3e;
		}
		p {
			text-align: center;
			color: #6c757d;
		}
		.instructions {
			background-color: #fff;
			padding: 20px;
			border-radius: 10px;
			box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
			margin-top: 20px;
			text-align: left;
		}
		.instructions h2 {
			color: #3e3e3e;
		}
		.instructions ol {
			list-style-type: none;
			padding-left: 0;
			counter-reset: item;
		}
		.instructions li {
			counter-increment: item;
			margin-bottom: 10px;
		}
		.instructions li::before {
			content: counter(item) ".";
			font-weight: bold;
			margin-right: 5px;
			color: #ffc107;
		}
		.bee-emoji {
			font-size: 100px;
			animation: bzz 0.1s infinite alternate;
			display: inline-block;
		}

		@keyframes bzz {
			0% {
				transform: translateX(-2px) rotate(-5deg);
			}
			100% {
				transform: translateX(2px) rotate(5deg);
			}
		}
	</style>
</head>
<body>
<div class="container">
	<h1>Bee Image Classification</h1>
	<p>In order to get the flag, classify 50 random images as one of the following types (case sensitive; send it exactly as displayed here!): Carniolan honey bee, Italian honey bee, Russian honey bee, VSH Italian honey bee, Western honey bee.</p>
	<p>You have 1 minute to classify all images after requesting them.</p>
	<p>Good luck!</p>

	<div class="instructions">
		<h2>Instructions</h2>
		<ol>
			<li>Request images from the /images endpoint.</li>
			<li>Classify each image by selecting the correct subspecies from any of the following: Carniolan honey bee, Italian honey bee, Russian honey bee, VSH Italian honey bee, Western honey bee.</li>
			<li>Send back a POST request to the /submit endpoint with a JSON object where the key is untouched from the /images response, but the value is the subspecies you classified the image as.</li>
			<li>If you classify all images correctly, you will receive the flag.</li>
		</ol>
	</div>

	<span class="bee-emoji">🐝</span>
	<!-- Credits go to kaggle.com for the dataset -->
</div>
</body>
</html>`

func init() {
	secretKey = make([]byte, 32)
	_, err := crrand.Read(secretKey)
	if err != nil {
		panic(err)
	}

	log.Printf("Secret key: %x\n", secretKey)

	loadBeeData("bee_data.csv")
}

func loadBeeData(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal("Error opening CSV file:", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	_, err = reader.Read()
	if err != nil {
		log.Fatal("Error reading CSV file:", err)
	}

	records, err := reader.ReadAll()
	if err != nil {
		log.Fatal("Error reading CSV records:", err)
	}

	for _, record := range records {
		if !contains(possibleSubspecies, record[5]) {
			continue
		}

		bee := Bee{
			File:       record[0],
			Subspecies: record[5],
		}
		bees = append(bees, bee)
	}
}

func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		userAgent := r.UserAgent()
		requestedPath := r.URL.Path

		log.Printf("%s - \"%s %s\" - User-Agent: %s\n", clientIP, r.Method, requestedPath, userAgent)

		w.Header().Set("Content-Encoding", "identity")

		next.ServeHTTP(w, r)
	})
}

func main() {
	http.Handle("/", loggingMiddleware(http.HandlerFunc(indexHandler)))
	http.Handle("/images", loggingMiddleware(http.HandlerFunc(imagesHandler)))
	http.Handle("/submit", loggingMiddleware(http.HandlerFunc(submitHandler)))

	log.Printf("Buzzing with %d entries", len(bees))

	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, htmlContent)
}

func imagesHandler(w http.ResponseWriter, r *http.Request) {
	var images []BeeImage
	var speciesCount int
	includedSpecies := make(map[string]bool)

	for len(images) < 50 {
		index := rand.Intn(len(bees))
		bee := bees[index]

		if !includedSpecies[bee.Subspecies] {
			includedSpecies[bee.Subspecies] = true
			speciesCount++
		}

		if speciesCount < 2 {
			continue
		}

		imagePath := imageFolder + bee.File
		imageData, err := os.ReadFile(imagePath)
		if err != nil {
			log.Println("Error reading image file:", err)
			continue
		}

		imageBase64 := base64.StdEncoding.EncodeToString(imageData)

		encryptedKey, err := encrypt(bee.File)
		if err != nil {
			http.Error(w, "Error encrypting image filename, please notify the challenge creator", http.StatusInternalServerError)
			log.Println("Error encrypting image filename:", err)
			return
		}

		images = append(images, BeeImage{
			encryptedKey: imageBase64,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(images)
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	var submissions map[string]string
	if r.Method != http.MethodPost {
		http.Error(w, errors.New("send a POST request").Error(), http.StatusMethodNotAllowed)
		return
	}
	err := json.NewDecoder(r.Body).Decode(&submissions)
	if err != nil {
		http.Error(w, errors.New("send a valid JSON (is it a list where the key is the untouched token you received and the value is the subspecies?)").Error(), http.StatusBadRequest)
		return
	}

	var correctCount int
	uniqueSpecies := make(map[string]bool)
	for encryptedKey, recognizedSpecies := range submissions {
		decryptedKey, err := decrypt(encryptedKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var found bool
		for _, bee := range bees {
			if bee.File == decryptedKey {
				found = true
				if isValidSolution(recognizedSpecies, bee) {
					correctCount++
					uniqueSpecies[recognizedSpecies] = true
				}
				break
			}
		}
		if !found {
			fmt.Println("Encrypted filename not found:", decryptedKey)
		}
	}

	if correctCount == 50 && len(uniqueSpecies) < 2 {
		fmt.Fprintf(w, "Technically you classified all images correctly, but you need to classify at least 2 different species.")
		log.Printf("%s - tried to outsmart the challenge by classifying only one species\n", r.RemoteAddr)
		return
	}

	if correctCount == 50 {
		go sendDiscordWebhook(r.RemoteAddr, fmt.Sprintf("```%s```", formatHeaders(r.Header)))
		log.Printf("%s - solved the challenge\n", r.RemoteAddr)
		fmt.Fprintf(w, "Congratulations! Here is the flag: %s", flag)
	} else {
		fmt.Fprintf(w, "You did not classify all 50 images correctly. Please try again.")
	}
}

func isValidSolution(solution string, bee Bee) bool {
	return solution == bee.Subspecies
}

func encrypt(filename string) (string, error) {
	filenameWithTime := fmt.Sprintf("%s$$%d", filename, time.Now().Unix())

	plaintext := []byte(filenameWithTime)

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(crrand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	encrypted := append(nonce, ciphertext...)

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func decrypt(encryptedKey string) (string, error) {
	encrypted, err := base64.URLEncoding.DecodeString(encryptedKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encrypted) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	parts := strings.SplitN(string(plaintext), "$$", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid format")
	}
	filename, timestampStr := parts[0], parts[1]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", err
	}
	if time.Since(time.Unix(timestamp, 0)) > time.Minute {
		return "", fmt.Errorf("you took too long to classify the image")
	}

	return filename, nil
}
