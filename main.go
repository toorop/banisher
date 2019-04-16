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
	b.banished[ip] = time.Now().Add(time.Duration(180) * time.Minute).Unix()
	log.Printf("%s added", ip)
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
type parser struct {
	rules []rule
}

func (p parser) Write(in []byte) (n int, err error) {
	n = len(in)
	entry := string(in)
	//log.Println(entry)
	for _, rule := range p.rules {
		if rule.Match.Match(in) {
			ip := rule.RegexIP.FindString(entry)
			log.Printf("%s match %s", ip, rule.Name)
			go banisher.Add(ip)
			break
		}
	}
	return n, nil
}

// implements Write interface
func (p parser) WriteOld(in []byte) (l int, err error) {
	l = len(in)
	entry := string(in)
	log.Println(entry)
	ip := ipv4Regex.FindString(entry)
	log.Println(ip)
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
	} else if strings.Contains(entry, "smtpd") && (strings.Contains(entry, "ERROR auth") || strings.Contains(entry, "-client timeout")) {
		// time="2019-04-16T09:56:10.220728971+02:00" level=info msg="smtpd d4e055ce0a2b07c2f6989f3b5578b98eb0a84a8f-141.98.80.30:17606-client timeout"

		ip := reTmail.FindString(entry)
		if ip != "" {
			go banisher.Add(ip)
		}

	}
	return l, nil
}

// main
func main() {
	var err error

	// get rules
	rules, err := parseRules("./rule.yml")
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(rules)
	banisher, err = NewBanisher()
	if err != nil {
		log.Fatalln(err)
	}

	// unban IP
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

	p := parser{
		rules: rules,
	}

	timeout := time.Duration(876000) * time.Hour

	if err = r.Follow(time.After(timeout), p); err != nil {
		log.Fatalln(err)
	}
}
