package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/coreos/go-systemd/sdjournal"
)

var banisher *Banisher
var config Config
var appVersion string

// main
func main() {
	var err error

	// get home (working path)
	home, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalln("failed to get home:", err)
	}

	// load parameters
	configFile := flag.String("conf", fmt.Sprintf("%s/config.yml", home), "configuration file")
	databaseFile := flag.String("db", fmt.Sprintf("%s/db.bdg", home), "database file")
	systemd := flag.Bool("systemd", false, "started by systemd")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()

	// show version
	if *showVersion {
		fmt.Printf("The Banisher v%s\n", appVersion)
		os.Exit(0)
	}

	// check if root privileges
	if !isRoot() {
		log.Fatalln("root privileges are required")
	}

	// remove timestamp on log
	if *systemd {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	// notify start of application with version
	log.Printf("Starting The Banisher v%s", appVersion)

	// load config
	config, err = loadConfig(*configFile)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// init banisher
	banisher, err = NewBanisher(*databaseFile)
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

	// follow the journalreader
	timeChan := make(chan time.Time, 1)
	go r.Follow(timeChan, p)

	// this handles killing the application gracefully
	wg := new(sync.WaitGroup)
	wg.Add(1)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func(wg *sync.WaitGroup) {
		<-c
		log.Println("Exiting The Banisher")
		wg.Done()
	}(wg)
	wg.Wait() //wait till we hear an interrupt

	// end follow of the journalreader
	timeChan <- time.Now()

	// clear filter rules
	if err = banisher.Clear(); err != nil {
		log.Fatalln(err)
	}
}
