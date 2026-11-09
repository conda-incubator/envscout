package cli

import "golang.org/x/sys/unix"

const (
	oscTermiosGet = unix.TIOCGETA
	oscTermiosSet = unix.TIOCSETA
)
