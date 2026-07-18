package transport

import (
	"sync"

	"github.com/xtls/xray-core/common/buf"
)

// Link is a utility for connecting between an inbound and an outbound proxy handler.
type Link struct {
	Reader buf.Reader
	Writer buf.Writer
}

var connectionLinkPool sync.Pool

// NewPooledLink creates a connection-scoped link that must be released after
// the synchronous dispatch path no longer retains it.
func NewPooledLink(reader buf.Reader, writer buf.Writer) *Link {
	link, _ := connectionLinkPool.Get().(*Link)
	if link == nil {
		link = new(Link)
	}
	link.Reader = reader
	link.Writer = writer
	return link
}

// ReleasePooledLink clears retained endpoints and returns a link for reuse.
func ReleasePooledLink(link *Link) {
	if link == nil {
		return
	}
	link.Reader = nil
	link.Writer = nil
	connectionLinkPool.Put(link)
}
