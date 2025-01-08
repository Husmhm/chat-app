package main

import (
	"chat_project/pkg"
	"encoding/base64"
	"log"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/gorilla/websocket"
)

var conn *websocket.Conn
var aesKey = []byte("exampleAESKey123")
var method = "aes" //or base 54

func connectToServer(url string) error {
	var err error
	conn, _, err = websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return err
	}

	_, keyMessage, err := conn.ReadMessage()
	if err != nil {
		return err
	}

	aesKey, err = base64.StdEncoding.DecodeString(string(keyMessage))
	if err != nil {
		return err
	}

	return nil
}

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("WebSocket Chat")

	messages := widget.NewMultiLineEntry()
	messages.Disable()

	input := widget.NewEntry()
	input.SetPlaceHolder("Type your message...")

	sendButton := widget.NewButton("Send", func() {
		message := strings.TrimSpace(input.Text)
		if message == "" || conn == nil {
			return
		}
		if method == "aes" {
			encryptedMessage, err := pkg.EncryptAES(message, aesKey)
			if err != nil {
				log.Println("Encryption error:", err)
				return
			}
			err = conn.WriteMessage(websocket.TextMessage, []byte(encryptedMessage))
			if err != nil {
				log.Println("Write error:", err)
				return
			}
		} else if method == "base64" {
			encryptedMessage := base64.StdEncoding.EncodeToString([]byte(message))
			err := conn.WriteMessage(websocket.TextMessage, []byte(encryptedMessage))
			if err != nil {
				log.Println("Write error:", err)
				return
			}
		}

		messages.SetText(messages.Text + "You: " + message + "\n")
		input.SetText("")
	})

	inputContainer := container.New(layout.NewBorderLayout(nil, nil, nil, sendButton), input, sendButton)

	chatContainer := container.NewBorder(nil, inputContainer, nil, nil, messages)
	myWindow.SetContent(chatContainer)

	go func() {
		err := connectToServer("ws://localhost:8080/ws")
		if err != nil {
			log.Println("Connection error:", err)
			messages.SetText("Error connecting to server: " + err.Error())
			return
		}

		log.Println("Connected to server")

		for {
			_, encryptedMessage, err := conn.ReadMessage()
			if err != nil {
				log.Println("Read error:", err)
				break
			}

			if method == "aes" {
				decryptedMessage, err := pkg.DecryptAES(string(encryptedMessage), aesKey)
				if err != nil {
					log.Println("Decryption error:", err)
					continue
				}
				messages.SetText(messages.Text + "Server: " + decryptedMessage + "\n")
			} else if method == "base64" {
				decryptedMessage, err := base64.StdEncoding.DecodeString(string(encryptedMessage))
				if err != nil {
					log.Println("Decoding error:", err)
					continue
				}
				messages.SetText(messages.Text + "Server: " + string(decryptedMessage) + "\n")
			}
		}
	}()

	myWindow.Resize(fyne.NewSize(500, 400))
	myWindow.ShowAndRun()
}
