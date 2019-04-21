package main

import "log"

// parser parse log line
type parser struct{}

// Write implement io.Writer interface
func (p parser) Write(in []byte) (n int, err error) {
	n = len(in)
	entry := string(in)
	for _, rule := range config.Rules {
		if rule.Match.Match(in) {
			//ip := rule.RegexIP.FindString(entry)
			//log.Println(entry)
			ips := ipv4Regex.FindAllString(entry, -1)
			if uint(len(ips)) < rule.IPpos+1 {
				log.Printf("no ip found at position %d for %s", rule.IPpos, entry)
				break
			}
			ip := ips[rule.IPpos]
			//log.Printf("%s match %s", ip, rule.Name)
			go banisher.Add(ip, rule.Name)
			break
		}
	}
	return n, nil
}
