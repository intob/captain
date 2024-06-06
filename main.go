package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"lukechampine.com/blake3"
)

type app struct {
	payload, key []byte
	hasher       *blake3.Hasher
}

type cmd struct {
	Name    string
	Args    []string
	Created time.Time
	Sum     string
}

func main() {
	key := flag.String("key", "", "authentication token")
	mode := flag.String("mode", "send", "operating mode: send | serve | obey")
	target := flag.String("target", "", "for send and obey modes")
	poll := flag.Duration("poll", 10*time.Second, "polling interval for obey mode")
	flag.Parse()
	if len(*key) == 0 {
		fmt.Println("missing key")
		os.Exit(1)
	}
	keySum := blake3.Sum256([]byte(*key))
	hasher := blake3.New(32, keySum[:])
	switch strings.ToLower(*mode) {
	case "serve":
		err := http.ListenAndServe(":1992", &app{
			hasher: hasher,
			key:    []byte(*key),
		})
		if err != nil {
			panic(err)
		}
	case "obey":
		var lastSum []byte
		for {
			time.Sleep(*poll)
			resp, err := http.Get(*target)
			if err != nil {
				fmt.Println(err)
				continue
			}
			c := &cmd{}
			dec := json.NewDecoder(resp.Body)
			err = dec.Decode(c)
			if err != nil {
				fmt.Println(err)
				continue
			}
			csum, err := hex.DecodeString(c.Sum)
			if err != nil {
				fmt.Println(err)
				continue
			}
			if bytes.Equal(csum, lastSum) {
				continue
			}
			// cmd cannot be replayed after poll duration
			err = verify(c, hasher, *poll)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Printf("will execute: %+v\n", c)
			oscmd := exec.Command(c.Name, c.Args...)
			err = oscmd.Run()
			if err != nil {
				fmt.Println(err)
			}
		}
	case "send":
		if flag.NArg() == 0 {
			panic("too few arguments to send command")
		}
		c := &cmd{
			Name:    flag.Arg(0),
			Args:    make([]string, 0),
			Created: time.Now(),
		}
		if flag.NArg() > 1 {
			c.Args = append(c.Args, flag.Args()[1:]...)
		}
		c.Sum = hex.EncodeToString(sign(c, hasher))
		payload, err := json.Marshal(c)
		if err != nil {
			panic(err)
		}
		buf := bytes.NewBuffer(payload)
		resp, err := http.Post(*target, "application/json", buf)
		if err != nil {
			panic(err)
		}
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(respBody))
	default:
		panic("unrecognised mode " + *mode)
	}
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Write(a.payload)
	case "POST":
		dec := json.NewDecoder(r.Body)
		c := &cmd{}
		err := dec.Decode(c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = verify(c, a.hasher, 200*time.Millisecond) // 200ms should be ok
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		a.payload, err = json.Marshal(c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("ok"))
	}
}

func sign(c *cmd, h *blake3.Hasher) []byte {
	h.Reset()
	h.Write(ttb(c.Created))
	h.Write([]byte(c.Name))
	for _, arg := range c.Args {
		h.Write([]byte(arg))
	}
	return h.Sum(nil)
}

func verify(c *cmd, h *blake3.Hasher, ttl time.Duration) error {
	// Don't accept payloads older than 200ms to prevent replays.
	// Not perfect, but good enough for now.
	if time.Since(c.Created) > ttl {
		return errors.New("payload expired")
	}
	csum, err := hex.DecodeString(c.Sum)
	if err != nil {
		return fmt.Errorf("failed to decode sig hex: %w", err)
	}
	h.Reset()
	h.Write(ttb(c.Created))
	h.Write([]byte(c.Name))
	for _, arg := range c.Args {
		h.Write([]byte(arg))
	}
	sum := h.Sum(nil)
	if !bytes.Equal(sum, csum) {
		return errors.New("invalid checksum")
	}
	return nil
}

func ttb(t time.Time) []byte {
	milli := t.UnixNano() / 1000000
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(milli))
	return bytes
}
