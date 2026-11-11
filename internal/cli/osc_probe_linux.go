package cli

import "golang.org/x/sys/unix"

const (
	oscTermiosGet = unix.TCGETS
	oscTermiosSet = unix.TCSETS
)
