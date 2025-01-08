package main

import (
	"chat_project/pkg"
	"encoding/base64"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}
var method = "aes" // or base 64

type Client struct {
	conn *websocket.Conn
	key  []byte
}

var clients = make(map[*Client]bool)
var mutex = &sync.Mutex{}

func broadcastMessage(sender *Client, encryptedMessage string) {
	mutex.Lock()
	defer mutex.Unlock()

	for client := range clients {
		if client != sender {
			err := client.conn.WriteMessage(websocket.TextMessage, []byte(encryptedMessage))
			if err != nil {
				log.Println("Error sending message:", err)
				client.conn.Close()
				delete(clients, client)
			}
		}
	}
}

func handleConnection(conn *websocket.Conn) {
	defer conn.Close()

	key := []byte("exampleAESKey123") // Fixed AES key
	conn.WriteMessage(websocket.TextMessage, []byte(base64.StdEncoding.EncodeToString(key)))

	client := &Client{conn: conn, key: key}
	mutex.Lock()
	clients[client] = true
	mutex.Unlock()

	log.Println("New client connected")

	for {
		_, encryptedMessage, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		if method == "aes" {
			decryptedMessage, err := pkg.DecryptAES(string(encryptedMessage), key)
			if err != nil {
				log.Println("Decryption error:", err)
				continue
			}
			log.Printf("Client says: %s (Encrypted: %s)", decryptedMessage, encryptedMessage)

			encryptedBroadcast, err := pkg.EncryptAES(decryptedMessage, key)
			if err != nil {
				log.Println("Encryption error:", err)
				continue
			}

			broadcastMessage(client, encryptedBroadcast)
		} else if method == "base64" {
			decryptedMessage, err := base64.StdEncoding.DecodeString(string(encryptedMessage))
			if err != nil {
				log.Println("Decoding error:", err)
				continue
			}
			log.Printf("Client says: %s (Encrypted: %s)", string(decryptedMessage), encryptedMessage)

			encryptedBroadcast := base64.StdEncoding.EncodeToString(decryptedMessage)
			broadcastMessage(client, encryptedBroadcast)
		}
	}

	mutex.Lock()
	delete(clients, client)
	mutex.Unlock()
	log.Println("Client disconnected")
}

func main() {
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Upgrade error:", err)
			return
		}

		handleConnection(conn)
	})

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
