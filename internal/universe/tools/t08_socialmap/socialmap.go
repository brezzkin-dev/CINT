package t08_socialmap

import (
	core "github.com/ollie/phantomfs/internal/universe/core"
	"github.com/ollie/phantomfs/internal/universe/tools/t05_userfinder"
)

func Run(user string) (*core.Result, error) {
	r, err := t05_userfinder.Run(user)
	if err != nil {
		return nil, err
	}
	r.Tool = "socialmap"
	r.AddExtra("note", "cross-platform identity presence from userfinder")
	return r, nil
}
