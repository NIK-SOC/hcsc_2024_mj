package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// doesn't matter what you put here, since it runs in a goroutine
const webhookURL = "http://placeholder"

type DiscordWebhookPayload struct {
	Content string `json:"content"`
	Embeds  []struct {
		Title  string `json:"title"`
		Fields []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Inline bool   `json:"inline"`
		} `json:"fields"`
		Color int `json:"color"`
	} `json:"embeds"`
}

func formatHeaders(headers http.Header) string {
	var formattedHeaders string

	for key, values := range headers {
		formattedHeaders += fmt.Sprintf("%s: %s\n", key, values[0])
	}

	if len(formattedHeaders) > 1000 {
		formattedHeaders = formattedHeaders[:1000]
	}

	return formattedHeaders
}

func sendDiscordWebhook(ipAddress, requestHeaders string) {
	host, _, err := net.SplitHostPort(ipAddress)
	if err != nil {
		host = ipAddress
	}
	payload := DiscordWebhookPayload{
		Content: "Someone got the flag on ThereOTT!",
		Embeds: []struct {
			Title  string `json:"title"`
			Fields []struct {
				Name   string `json:"name"`
				Value  string `json:"value"`
				Inline bool   `json:"inline"`
			} `json:"fields"`
			Color int `json:"color"`
		}{
			{
				Title: "Client Information",
				Fields: []struct {
					Name   string `json:"name"`
					Value  string `json:"value"`
					Inline bool   `json:"inline"`
				}{
					{
						Name:   "Client IP Address",
						Value:  "?#CLIENT_IP=" + host + "#?",
						Inline: false,
					},
					{
						Name:   "Client Request Headers",
						Value:  requestHeaders,
						Inline: false,
					},
				},
				Color: 3066993,
			},
		},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Failed to marshal JSON:", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadJSON))
	if err != nil {
		fmt.Println("Failed to send Discord webhook:", err)
		return
	}
	defer resp.Body.Close()
}
