package rule

import (
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"

	mDNS "github.com/miekg/dns"
)

var _ RuleItem = (*DomainLabelCountItem)(nil)

type DomainLabelCountItem struct {
	labelCounts []uint32
}

func NewDomainLabelCountItem(labelCounts []uint32) *DomainLabelCountItem {
	return &DomainLabelCountItem{
		labelCounts: labelCounts,
	}
}

func (r *DomainLabelCountItem) Match(metadata *adapter.InboundContext) bool {
	var domainHost string
	if metadata.Domain != "" {
		domainHost = metadata.Domain
	} else {
		domainHost = metadata.Destination.Fqdn
	}
	if domainHost == "" {
		return false
	}
	return slices.Contains(r.labelCounts, uint32(mDNS.CountLabel(mDNS.CanonicalName(domainHost))))
}

func (r *DomainLabelCountItem) String() string {
	description := "domain_label_count="
	pLen := len(r.labelCounts)
	if pLen == 1 {
		description += F.ToString(r.labelCounts[0])
	} else {
		description += "[" + strings.Join(F.MapToString(r.labelCounts), " ") + "]"
	}
	return description
}
