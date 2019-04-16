package main

import (
	"io/ioutil"
	"log"
	"regexp"

	"gopkg.in/yaml.v3"
)

type rule struct {
	Name    string
	Match   *regexp.Regexp
	RegexIP *regexp.Regexp
}

type ruleRaw struct {
	Name    string
	Match   string
	RegexIP string `yaml:"regexIP"`
}

// parseRules parses rule file
func parseRules(path string) (rules []rule, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rulesRaw []ruleRaw
	err = yaml.Unmarshal(data, &rulesRaw)
	if err != nil {
		return
	}
	// parse (or not regex)
	for _, rr := range rulesRaw {
		r := rule{
			Name: rr.Name,
		}

		// Match mus be a valide regex
		r.Match, err = regexp.Compile(rr.Match)
		if err != nil {
			return nil, err
		}

		// RegexIp must be a key for knownRegex or a valid regex
		log.Printf("regexIP |%s|", rr.RegexIP)
		if rr.RegexIP == "ipv4" {
			log.Println("ON a une regex IPv4")
			r.RegexIP = ipv4Regex
		} else {
			r.RegexIP, err = regexp.Compile(rr.RegexIP)
			if err != nil {
				return nil, err
			}
		}
		rules = append(rules, r)
	}

	return
}
