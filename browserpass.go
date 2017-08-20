package browserpass

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dannyvankooten/browserpass/pass"
)

// Login represents a single pass login.
type Login struct {
	Username string `json:"u"`
	Password string `json:"p"`
	Other map[string]string `json:"other"`
}

var endianness = binary.LittleEndian

// msg defines a message sent from a browser extension.
type msg struct {
	Action string `json:"action"`
	Domain string `json:"domain"`
	Entry  string `json:"entry"`
}

// Run starts browserpass.
func Run(stdin io.Reader, stdout io.Writer, s pass.Store) error {
	for {
		// Get message length, 4 bytes
		var n uint32
		if err := binary.Read(stdin, endianness, &n); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		// Get message body
		var data msg
		lr := &io.LimitedReader{R: stdin, N: int64(n)}
		if err := json.NewDecoder(lr).Decode(&data); err != nil {
			return err
		}

		var resp interface{}
		switch data.Action {
		case "search":
			list, err := s.Search(data.Domain)
			if err != nil {
				return err
			}
			resp = list
		case "get":
			rc, err := s.Open(data.Entry)
			if err != nil {
				return err
			}
			defer rc.Close()
			login, err := readLoginGPG(rc)
			if err != nil {
				return err
			}
			if login.Other["username"] == "" {
				login.Other["username"] = guessUsername(data.Entry)
			}
			resp = login.Other
		default:
			return errors.New("Invalid action")
		}

		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(resp); err != nil {
			return err
		}

		if err := binary.Write(stdout, endianness, uint32(b.Len())); err != nil {
			return err
		}
		if _, err := b.WriteTo(stdout); err != nil {
			return err
		}
	}
}

// readLoginGPG reads a encrypted login from r using the system's GPG binary.
func readLoginGPG(r io.Reader) (*Login, error) {
	// Assume gpg1
	gpgbin := "gpg"
	opts := []string{"--decrypt", "--yes", "--quiet"}

	// Check if gpg2 is available
	gpg2check := exec.Command("gpg2", "--version")
	if err := gpg2check.Run(); err == nil {
		gpgbin = "gpg2"
		opts = append(opts, "--use-agent", "--batch")
	}

	// Tell gpg to read from stdin
	opts = append(opts, "-")

	// Run gpg
	cmd := exec.Command(gpgbin, opts...)

	cmd.Stdin = r

	rc, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Read decrypted output
	login, err := parseLogin(rc)
	if err != nil {
		return nil, err
	}
	rc.Close()

	if err := cmd.Wait(); err != nil {
		return nil, errors.New(err.Error() + "\n" + errbuf.String())
	}
	return login, nil
}

// parseLogin parses a login and a password from a decrypted password file.
func parseLogin(r io.Reader) (*Login, error) {
	login := new(Login)

	login.Other = make(map[string]string)

	scanner := bufio.NewScanner(r)

	// The first line is the password
	scanner.Scan()
	login.Password = scanner.Text()


	re := regexp.MustCompile(`^(?P<key>[[:alnum:]\.]+?)\:\s*(?P<value>.+)$`)
	for scanner.Scan() {
		line := scanner.Text()

		match  := re.FindStringSubmatch(line)

		if (match != nil) {
			key, value := match[1], match[2]
			login.Other[key] = value
		}

	}
	login.Other["password"] = login.Password
	return login, nil
}

// guessLogin tries to guess a username from an entry's name.
func guessUsername(name string) string {
	if strings.Count(name, "/") >= 1 {
		return filepath.Base(name)
	}
	return ""
}
