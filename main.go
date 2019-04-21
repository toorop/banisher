package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/coreos/go-systemd/sdjournal"
)

var banisher *Banisher
var home string
var config Config

// main
func main() {
	var err error

	// get home (working path)
	home, err = filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalln("failed to os.Getwd():", err)
	}

	// load config
	config, err = loadConfig(fmt.Sprintf("%s/config.yml", home))
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	// init banisher
	banisher, err = NewBanisher()
	if err != nil {
		log.Fatalln(err)
	}
	defer banisher.db.Close()

	// restore rule from DB
	if err = banisher.Restore(); err != nil {
		log.Fatalln(err)
	}

	// remove expired iptables rules
	go banisher.GC()

	r, err := sdjournal.NewJournalReader(sdjournal.JournalReaderConfig{
		Since: time.Duration(-5) * time.Second,
	})
	if err != nil {
		log.Fatalln("failed to get journal reader:", err)
	}
	if r == nil {
		log.Fatalln("journal reader is nil")
	}
	defer r.Close()

	p := parser{}

	if err = r.Follow(time.After(time.Duration(876000)*time.Hour), p); err != nil {
		log.Fatalln(err)
	}

}
