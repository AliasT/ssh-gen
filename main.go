package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"

	"log"
	"os"
	"os/exec"
	"path"
	"strings"

	"golang.design/x/clipboard"
	"golang.org/x/crypto/ssh"
)

// start. ssh-agent bash
func main() {
	var filename string
	flag.StringVar(&filename, "filename", "id_rsa", "输入文件名")
	dirname, err := os.UserHomeDir()

	if err != nil {
		log.Fatalln("获取用户目录失败")
	}

	filename = path.Join(dirname, ".ssh", filename)
	filename = strings.ReplaceAll(filename, "\\", "/")

	log.Printf("%s", filename)

	savePrivateFileTo := filename
	savePublicFileTo := strings.Join([]string{filename, ".pub"}, "")

	log.Printf("%s", savePublicFileTo)

	privateKey, err := generatePrivateKey(4096)
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	err = writeKeyToFile(privateKeyBytes, savePrivateFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile([]byte(publicKeyBytes), savePublicFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = clipboard.Init()

	if err != nil {
		log.Fatal(err.Error())
	}

	clipboard.Write(clipboard.FmtText, publicKeyBytes)
	out, err := exec.Command("ssh-agent", "bash").Output()
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Println(out)
	out, err = exec.Command("ssh-add", filename).Output()

	if err != nil {
		log.Fatal(err.Error())
	}

	log.Println(out)

	// github token 自动上传并验证
	// out, err = exec.Command("git", "-T", "git@github.com").Output()
	// if err != nil {
	// 	log.Fatal(out)
	// }
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := os.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}
