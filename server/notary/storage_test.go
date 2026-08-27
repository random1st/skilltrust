package notary_test

import (
	"testing"

	"github.com/random1st/skilltrust/server/notary"
	"github.com/random1st/skilltrust/server/notary/notarytest"
)

func TestFileStorageMeetsTheContract(t *testing.T) {
	notarytest.Contract(t, func(t *testing.T) notary.Storage {
		return notary.NewFileStorage(t.TempDir())
	})
}
