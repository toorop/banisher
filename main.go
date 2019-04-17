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

// main
func main() {
	var err error

	// get home (working path)
	home, err = filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalln("failed to os.Getwd():", err)
	}

	// get rules
	rules, err := parseRules(fmt.Sprintf("%s/rule.yml", home))
	if err != nil {
		log.Fatalln("failed to parse rules:", err)
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

	p := parser{
		rules: rules,
	}

	timeout := time.Duration(876000) * time.Hour

	if err = r.Follow(time.After(timeout), p); err != nil {
		log.Fatalln(err)
	}
}
