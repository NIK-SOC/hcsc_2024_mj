package main

import (
	"errors"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/pojntfx/go-nbd/pkg/client"
	"github.com/pojntfx/go-nbd/pkg/server"
)

type FileBackend struct {
	file *os.File
}

func NewFileBackend(file *os.File) *FileBackend {
	return &FileBackend{file}
}

func (b *FileBackend) ReadAt(p []byte, off int64) (n int, err error) {
	return b.file.ReadAt(p, off)
}

func (b *FileBackend) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, errors.New("you wouldn't destroy the challenge for others, would you?")
}

func (b *FileBackend) Size() (int64, error) {
	stat, err := b.file.Stat()
	if err != nil {
		return -1, err
	}

	return stat.Size(), nil
}

func (b *FileBackend) Sync() error {
	return b.file.Sync()
}

func main() {
	imagePath := "fs.img"

	file, err := os.OpenFile(imagePath, os.O_RDONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open image file: %v", err)
	}
	defer file.Close()

	backend := NewFileBackend(file)

	portStr := os.Getenv("BACKEND_PORT")
	if portStr == "" {
		portStr = "1234"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Failed to convert BACKEND_PORT to integer: %v", err)
	}

	l, err := net.Listen("tcp", ":"+portStr)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	log.Printf("Listening on port %d", port)

	clients := 0
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("Could not accept connection, continuing:", err)
			continue
		}

		clientAddr := conn.RemoteAddr().String()

		clients++
		log.Printf("%v clients connected, IP: %v", clients, clientAddr)

		go func() {
			defer func() {
				_ = conn.Close()
				clients--

				if err := recover(); err != nil {
					log.Printf("Client disconnected with error: %v", err)
				}

				log.Printf("%v clients connected", clients)
			}()

			if err := server.Handle(
				conn,
				[]*server.Export{
					{
						Name:        "",
						Description: "Not a bad day challenge",
						Backend:     backend,
					},
				},
				&server.Options{
					ReadOnly:           true,
					MinimumBlockSize:   uint32(1),
					PreferredBlockSize: client.MaximumBlockSize,
					MaximumBlockSize:   uint32(0xffffffff),
					SupportsMultiConn:  true,
				}); err != nil {
				log.Printf("Failed to handle connection: %v", err)
			}
		}()
	}
}
