package main

import (
	"bytes"
	"html/template"
)

type PageData struct {
	Reason string
}

var tmpl *template.Template

func init() {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Skid Detected!!!!4444!!!!</title>
<meta name="description" content="Advanced Anti-DDoS protection triggered. No dodos please">
<style>
  body {
    margin: 0;
    padding: 0;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    background: linear-gradient(to right, #000 0%, #222 100%);
    animation: vibratingBackground 2s infinite;
  }
  
  .container {
    width: 400px;
    height: 350px;
    background-color: #222;
    border: 10px solid red;
    border-radius: 20px;
    text-align: center;
    position: relative;
    box-shadow: 0 0 20px rgba(255, 0, 0, 0.5);
    overflow: hidden;
  }

  .container img {
    border-radius: 10px;
    margin-top: 20px;
    box-shadow: 0 0 10px rgba(255, 0, 0, 0.5);
  }

  .container p {
    color: #fff;
    font-size: 18px;
    margin-top: 10px;
    text-shadow: 2px 2px 5px rgba(255, 0, 0, 0.5);
  }

  .bottom-right-image {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 150px;
    height: auto;
  }

  .skid-busted {
    position: absolute;
    bottom: 0;
    right: 0;
    background-color: rgba(255, 255, 255, 0.7);
    padding: 5px 10px;
    border-radius: 5px;
    font-weight: bold;
    z-index: 1; /* ensure it appears on top of the image */
  }

  @keyframes vibratingBackground {
    0%, 100% {
      background: linear-gradient(to right, #ff0000 0%, #0000ff 100%);
    }
    50% {
      background: linear-gradient(to right, #0000ff 0%, #ff0000 100%);
    }
  }
</style>
</head>
<body>
  <div class="container">
    <p><b>
    A L E R T
    </b>
    </p>
    <img src="https://media1.tenor.com/m/K1drQQHpGLkAAAAC/alert-siren.gif" alt="Alert Siren" width="200">
    <p>REASON: <span id="reason">{{.Reason}}</span></p>
  </div>
  <div class="skid-busted">Skid Busted</div>
  <img src="https://media.tenor.com/G5Xz2KGKMqkAAAAi/wojak-pointing.gif" alt="Wojak" class="bottom-right-image">
</body>
</html>`

	var err error
	tmpl, err = template.New("errorTemplate").Parse(htmlTemplate)
	if err != nil {
		panic(err)
	}
}

func GenerateErrorPage(reason string) string {
	data := PageData{
		Reason: reason,
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		panic(err)
	}

	return buf.String()
}
