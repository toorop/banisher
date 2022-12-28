package main

import (
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	badger "github.com/dgraph-io/badger/v3"
	"github.com/nadoo/ipset"
)

const ipsetName = "banisher"

// Banisher is THE banisher
type Banisher struct {
	sync.Mutex
	db  *badger.DB
	IPT *iptables.IPTables
}

func NewBanisher(databaseFile string) (b *Banisher, err error) {
	b = new(Banisher)

	// badger options
	var options badger.Options
	if databaseFile == ":memory:" {
		options = badger.DefaultOptions("").WithInMemory(true)
	} else {
		options = badger.DefaultOptions(databaseFile)
		options.SyncWrites = true
	}
	options.Logger = nil

	// open badger database
	b.db, err = badger.Open(options)
	if err != nil {
		return nil, err
	}

	// iptables binding
	b.IPT, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	// ipset binding
	if err = ipset.Init(); err != nil {
		return nil, err
	}

	return
}

// Add ban an IP
func (b *Banisher) Add(ip, ruleName string) {
	var err error

	// IP validation
	ok := net.ParseIP(ip)
	if ok == nil {
		return
	}

	// whitelisted
	if config.isIPWhitelisted(ip) {
		return
	}

	b.Lock()
	defer b.Unlock()

	// Already in DB ?
	found := false
	err = b.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(ip))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				err = nil
			}
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		log.Println("failed to check in DB:", err)
		return
	}
	if found {
		return
	}

	// ipset
	if err = b.filterIP(ip); err != nil {
		log.Println("failed to add an entry to ipset:", err)
		return
	}

	// add to badger
	err = b.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(ip), []byte(strconv.FormatInt(time.Now().Add(time.Duration(config.DefaultBanishmentDuration)*time.Second).Unix(), 10)))
	})

	if err != nil {
		log.Printf("failed to add %s in db: %s", ip, err)
		// remove from ipset
		if err = b.unFilterIP(ip); err != nil {
			log.Printf("failed to remove %s from ipset: %s", ip, err)
		}
		return
	}
	log.Printf("%s: %s banned", ruleName, ip)
}

// Remove unban an IP
func (b *Banisher) Remove(ip string) {
	var err error
	if err = b.unFilterIP(ip); err != nil {
		log.Printf("failed to remove %s from ipset: %s", ip, err)
		return
	}
	err = b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(ip))
	})
	if err != nil {
		log.Printf("failed to remove %s from db: %s", ip, err)
		return
	}
	log.Printf("%s unbanned", ip)
}

// Restore restore iptables rules from DB
func (b *Banisher) Restore() error {

	// create an empty ipset for The Banisher
	ipset.Destroy(ipsetName)
	if err := ipset.Create(ipsetName); err != nil {
		return err
	}
	if err := ipset.Flush(ipsetName); err != nil {
		return err
	}

	// create the iptable rule if it does not exist
	exists, err := b.IPT.Exists("filter", "INPUT", "-m", "set", "--match-set", ipsetName, "src", "-j", "DROP")
	if err != nil {
		return err
	}
	if !exists {
		if err := b.IPT.Insert("filter", "INPUT", 1, "-m", "set", "--match-set", ipsetName, "src", "-j", "DROP"); err != nil {
			return err
		}
	}

	if !b.db.Opts().InMemory {
		err := b.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchSize = 20
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				ip := it.Item().Key()
				if err := b.filterIP(string(ip)); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	} else {
		return nil
	}
}

// GC remove expired banishment
func (b *Banisher) GC() {
	for {
		now := time.Now().Unix()
		err := b.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchSize = 20
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				ip := it.Item().Key()
				err := it.Item().Value(func(val []byte) error {
					ts, err := strconv.ParseInt(string(val), 10, 64)
					if err != nil {
						return err
					}
					if ts < now {
						b.Remove(string(ip))
					}
					return nil
				})
				if err != nil {
					log.Println("failed to parse string:", err)
				}
			}
			return nil
		})
		if err != nil {
			log.Println("failed in GC loop:", err)
		}
		time.Sleep(time.Duration(5) * time.Minute)
	}
}

func (b *Banisher) Clear() error {

	// remove iptable rule
	if err := b.IPT.Delete("filter", "INPUT", "-m", "set", "--match-set", ipsetName, "src", "-j", "DROP"); err != nil {
		return err
	}

	// clear and remove ipset
	if err := ipset.Flush(ipsetName); err != nil {
		return err
	}
	ipset.Destroy(ipsetName)

	return nil
}

func (b *Banisher) filterIP(ip string) error {
	return ipset.Add(ipsetName, ip)
}

func (b *Banisher) unFilterIP(ip string) error {
	return ipset.Del(ipsetName, ip)
}
