package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DefaultBanishmentDuration uint
	Whitelist                 []string
	Rules                     []rule
}

func loadConfig(path string) (conf Config, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, err
	}

	m := make(map[interface{}]interface{})

	err = yaml.Unmarshal([]byte(data), &m)
	if err != nil {
		return
	}
	//fmt.Printf("--- m:\n%v\n\n", m)

	// DefaultBanishmentDuration
	conf.DefaultBanishmentDuration = uint(m["defaultBanishmentDuration"].(int))

	// whitelist
	if m["whitelist"] != nil {
		for _, ip := range m["whitelist"].([]interface{}) {
			if net.ParseIP(ip.(string)) == nil {
				return conf, fmt.Errorf("%s is not a valid IP for whitelist", ip.(string))
			}
			if conf.isIPWhitelisted(ip.(string)) {
				return conf, fmt.Errorf("%s appears multiple time in your whitelist", ip.(string))

			}
			conf.Whitelist = append(conf.Whitelist, ip.(string))
		}
	}

	// rules
	for _, r := range m["rules"].([]interface{}) {
		rule2add := rule{}

		rs := r.(map[interface{}]interface{})

		// name
		if rs["name"] == nil {
			return conf, errors.New("required field 'name' is missing in a rule")
		}
		rule2add.Name = rs["name"].(string)

		// ippos
		if rs["IPpos"] != nil {
			rule2add.IPpos = uint(rs["IPpos"].(int))
		} else {
			rule2add.IPpos = 0
		}

		// match
		if rs["match"] == nil {
			return conf, errors.New("required field 'match' is missing in a rule")
		}
		// to regex
		rule2add.Match, err = regexp.Compile(rs["match"].(string))
		if err != nil {
			return conf, fmt.Errorf("failed to compile regex: %s, %v", rs["match"].(string), err)
		}

		// append rule
		conf.Rules = append(conf.Rules, rule2add)

	}
	return
}

// check if ip is whitelisted
func (c Config) isIPWhitelisted(ip string) bool {
	for _, ipw := range c.Whitelist {
		if ip == ipw {
			return true
		}
	}
	return false
}
