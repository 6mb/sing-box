package rule

import (
	"context"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
)

var _ RuleItem = (*SearchDomainAvailableItem)(nil)

type SearchDomainAvailableItem struct {
	ctx           context.Context
	transportTags []string
	transports    []adapter.DNSTransportWithSearchDomain
}

func NewSearchDomainAvailableItem(ctx context.Context, transportTags []string) *SearchDomainAvailableItem {
	return &SearchDomainAvailableItem{
		ctx:           ctx,
		transportTags: transportTags,
	}
}

func (r *SearchDomainAvailableItem) Start() error {
	transportManager := service.FromContext[adapter.DNSTransportManager](r.ctx)
	for _, transportTag := range r.transportTags {
		rawTransport, loaded := transportManager.Transport(transportTag)
		if !loaded {
			return E.New("DNS server not found: ", transportTag)
		}
		transportWithSearchDomain, withSearchDomain := rawTransport.(adapter.DNSTransportWithSearchDomain)
		if !withSearchDomain {
			return E.New("DNS server type does not support search_domain_available: ", rawTransport.Type())
		}
		r.transports = append(r.transports, transportWithSearchDomain)
	}
	return nil
}

func (r *SearchDomainAvailableItem) Match(metadata *adapter.InboundContext) bool {
	for _, transport := range r.transports {
		if transport.HasSearchDomain() {
			return true
		}
	}
	return false
}

func (r *SearchDomainAvailableItem) String() string {
	description := "search_domain_available="
	pLen := len(r.transportTags)
	if pLen == 1 {
		description += F.ToString(r.transportTags[0])
	} else {
		description += "[" + strings.Join(F.MapToString(r.transportTags), " ") + "]"
	}
	return description
}
