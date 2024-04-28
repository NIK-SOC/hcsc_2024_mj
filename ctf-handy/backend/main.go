package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const welcomeAsciiArt = `      ,-'""` + "`" + `-,               
,'        ` + "`" + `.             
/    _,,,_   \            
/   ,'  |  ` + "`" + `\/\\           
/   /,--' ` + "`" + `--.  ` + "`" + `           
|   /      ___\_            
|  | /  ______|             
|  | |  |_' \'|             
\ ,' (   _) -` + "`" + `|             
'--- \ '-.-- /             
______/` + "`" + `--'--<              
|    |` + "`" + `-.  ,;/` + "`" + `` + "`" + `--._        
|    |-. _///     ,'` + "`" + `\      
|    |` + "`" + `-Y;'/     /  ,-'\    
|    | // <_    / ,'  ,-'\  
'----'// -- ` + "`" + `-./,' ,-'  \/  
|   //[==]     \,' \_.,-\  
|  //      ` + "`" + `  -- | \__.,-' 
// -[==]_      |   ____\ 
//          ` + "`" + `-- |--' |   \
    [==__,,,,--'    |-'" 
---""''             |    
hjm          ___...____/     
    --------------------.
           ,.        --.|
          /||\        /||
           ||        /  |
           ||       /   |
            |      /    |
`

func handleClient(conn net.Conn, charMap map[string]string) {
	defer conn.Close()

	done := make(chan bool)

	go func() {
		defer close(done)

		conn.Write([]byte(welcomeAsciiArt + "\n"))

		conn.Write([]byte("Beep, boop! Give me a message to encrypt: "))

		reader := bufio.NewReader(conn)
		message := make([]byte, 0, 200)
		for {
			part, err := reader.ReadBytes('\n')
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				conn.Write([]byte("Error reading message\n"))
				fmt.Println("Error reading message:", err)
				return
			}
			message = append(message, part...)
			if len(message) > 200 {
				break
			}
			if len(part) < bufio.MaxScanTokenSize || len(message) >= 200 {
				break
			}
		}
		messageStr := strings.ToLower(strings.TrimSpace(string(message)))

		encryptedMessage := ""
		for _, char := range messageStr {
			charStr := string(char)
			if encryptedChar, ok := charMap[charStr]; ok {
				encryptedMessage += encryptedChar
			} else {
				encryptedMessage += charStr
			}
		}

		conn.Write([]byte("Here ya go: "))
		conn.Write([]byte(encryptedMessage + "\n"))
	}()

	select {
	case <-done:
		return
	case <-time.After(30 * time.Second):
		conn.Write([]byte("\nConnection timed out\n"))
	}
}

func main() {
	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "1337"
	}

	chars := strings.Split("a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z", "/")
	encrypted := strings.Split("20/220/2220/30/330/3330/40/440/4440/50/550/5550/60/660/6660/70/770/7770/77770/80/880/8880/90/990/9990/99990", "/")
	charMap := make(map[string]string)
	for i, char := range chars {
		charMap[char] = encrypted[i]
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("Server listening on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			continue
		}
		go handleClient(conn, charMap)
	}
}
