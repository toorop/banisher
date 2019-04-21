package main

import (
	"regexp"
)

type rule struct {
	Name  string
	Match *regexp.Regexp
	IPpos uint
	Port  uint
}
