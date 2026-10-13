package proxyman

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/session"
)

const (
	// DefaultMuxMaxReuseTimes is the lifetime session budget of a Mux.Cool
	// connection when maxReuseTimes is 0, as it was before the option.
	DefaultMuxMaxReuseTimes = 128
	// MaxMuxMaxReuseTimes is the largest maxReuseTimes. Session IDs are 16-bit
	// and start at 1, so one connection never repeats an ID and leaves the
	// IDs above 60000 unused, as XTLS/Xray-core#4231 proposes.
	MaxMuxMaxReuseTimes = 60000
)

// ResolveMaxReuseTimes returns how many sessions one connection of the main
// Mux.Cool pool admits over its lifetime, or an error when maxReuseTimes is
// out of range.
func (c *MultiplexingConfig) ResolveMaxReuseTimes() (uint32, error) {
	switch n := c.GetMaxReuseTimes(); {
	case n == 0:
		return DefaultMuxMaxReuseTimes, nil
	case n < 0 || n > MaxMuxMaxReuseTimes:
		return 0, errors.New("mux maxReuseTimes ", n, " is outside 0-", MaxMuxMaxReuseTimes)
	default:
		return uint32(n), nil
	}
}

func BuildSniffingRequest(config *SniffingConfig) (session.SniffingRequest, error) {
	if config == nil {
		return session.SniffingRequest{}, nil
	}

	request := session.SniffingRequest{
		Enabled:                        config.Enabled,
		OverrideDestinationForProtocol: config.DestinationOverride,
		MetadataOnly:                   config.MetadataOnly,
		RouteOnly:                      config.RouteOnly,
	}
	for _, protocol := range config.DestinationOverride {
		switch protocol {
		case "http":
			request.OverrideProtocolMask |= session.SniffingOverrideHTTP
		case "tls":
			request.OverrideProtocolMask |= session.SniffingOverrideTLS
		}
	}
	if len(config.DomainsExcluded) > 0 {
		excludeForDomain, err := geodata.DomainReg.BuildDomainMatcher(config.DomainsExcluded)
		if err != nil {
			return session.SniffingRequest{}, err
		}
		request.ExcludeForDomain = excludeForDomain
	}
	if len(config.IpsExcluded) > 0 {
		excludeForIP, err := geodata.IPReg.BuildIPMatcher(config.IpsExcluded)
		if err != nil {
			return session.SniffingRequest{}, err
		}
		request.ExcludeForIP = excludeForIP
	}
	return request, nil
}
