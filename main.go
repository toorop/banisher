package main

import (
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/coreos/go-systemd/sdjournal"
)

var banisher *Banisher

var reTmail *regexp.Regexp

// Banisher is THE banisher
type Banisher struct {
	sync.Mutex
	banished map[string]int64
	IPT      *iptables.IPTables
}

func NewBanisher() (b *Banisher, err error) {
	b = new(Banisher)
	b.IPT, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}
	b.banished = make(map[string]int64)
	return
}

func (b *Banisher) Add(ip string) {
	var err error
	// validation
	ok := net.ParseIP(ip)
	if ok == nil {
		return
	}
	b.Lock()
	defer b.Unlock()

	// iptables
	if err = b.IPT.AppendUnique("filter", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		log.Println("add iptable rule failed:", err)
		return
	}
	b.banished[ip] = time.Now().Add(time.Duration(90) + time.Minute).Unix()
}

func (b *Banisher) Remove(ip string) error {
	log.Printf("%s removed", ip)
	if err := b.IPT.Delete("filter", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		return err
	}
	delete(b.banished, ip)
	return nil
}

func (b *Banisher) WatchBannishedTime() {
	for {
		now := time.Now().Unix()
		for ip, ts := range b.banished {
			log.Println(ip, ts, now)
			if ts < now {
				if err := b.Remove(ip); err != nil {
					log.Printf("b.Remove(%s) failed: %s", ip, err)
				}
			}
		}
		time.Sleep(time.Duration(1) * time.Minute)
	}
}

// parser is the ... parser
type parser struct{}

// implements Write interface
func (p parser) Write(in []byte) (l int, err error) {
	l = len(in)
	entry := string(in)
	//log.Println(entry)
	// dovecot
	if strings.Contains(entry, "imap-login:") && strings.Contains(entry, "auth failed") {
		parts := strings.Split(entry, ",")
		if len(parts) < 4 {
			return
		}

		jetteIP := strings.Split(strings.TrimSpace(parts[3]), "=")
		if len(jetteIP) != 2 {
			return
		}
		go banisher.Add(jetteIP[1])
		//
	} else if strings.Contains(entry, "smtpd") && strings.Contains(entry, "ERROR auth") {
		//log.Println(entry)
		parts := strings.Split(entry, " ")
		if len(parts) < 8 {
			return
		}

		ip := reTmail.FindString(parts[7])
		go banisher.Add(ip)

	}
	return l, nil
}

// main
func main() {
	var err error

	reTmail, err = regexp.Compile(`([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})`)
	if err != nil {
		log.Fatalln(err)
	}

	banisher, err = NewBanisher()
	if err != nil {
		log.Fatalln(err)
	}

	go banisher.WatchBannishedTime()

	r, err := sdjournal.NewJournalReader(sdjournal.JournalReaderConfig{
		Since: time.Duration(-5) * time.Second,
	})

	if err != nil {
		log.Fatalln(err)
	}
	if r == nil {
		log.Fatalln("reader is nil")
	}
	defer r.Close()

	p := parser{}

	timeout := time.Duration(876000) * time.Hour

	if err = r.Follow(time.After(timeout), p); err != nil {
		log.Fatalln(err)
	}
}
