package main

import (
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	IABytes   = 8
	ISDBits   = 16
	ASBits    = 48
	BGPASBits = 32

	asPartBits = 16
	asPartBase = 16
	asPartMask = (1 << asPartBits) - 1
	asParts    = ASBits / asPartBits

	ISDFmtPrefix = "ISD"
	ASFmtPrefix  = "AS"
)

func asParse(s string, sep string) (uint64, error) {
	if strings.Index(s, sep) == -1 {
		// Must be a BGP AS, parse as 32-bit decimal number
		as, err := strconv.ParseUint(s, 10, BGPASBits)
		if err != nil {
			// err.Error() will contain the original value
			return 0, serrors.WrapStr("Unable to parse AS", err)
		}
		return uint64(as), nil
	}
	parts := strings.Split(s, sep)
	if len(parts) != asParts {
		return 0, serrors.New("unable to parse AS: wrong number of separators",
			"expected", asParts, "actual", len(parts), "sep", sep, "raw", s)
	}
	var as uint64
	for i := 0; i < asParts; i++ {
		as <<= asPartBits
		v, err := strconv.ParseUint(parts[i], asPartBase, asPartBits)
		if err != nil {
			return 0, serrors.WrapStr("Unable to parse AS part", err, "raw", s)
		}
		as |= uint64(v)
	}
	return as, nil
}

func main() {

}
