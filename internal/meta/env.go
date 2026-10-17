package meta

import (
	"os"
	"strings"
)

func envPublicAppURL() string {
	v := strings.TrimSpace(os.Getenv("NEXT_PUBLIC_APP_URL"))
	return v
}
