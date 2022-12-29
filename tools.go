package main

import (
	"log"
	"os/user"
)

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}
