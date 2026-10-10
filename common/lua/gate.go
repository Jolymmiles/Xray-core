package lua

import "errors"

// ScriptsEnabled gates the routing and DNS scripts built on this package
// (XTLS/Xray-core#6823). The fork ships them disabled until two problems are
// solved (docs/FORK.md): Pool creates one state per concurrent call without a
// bound, and a plain bound would deadlock a routing script whose DNS lookup
// re-enters routing; scripts also load in Start, after inbounds accept
// connections, so early connections and the TUN DNS takeover probe see only
// the JSON rules. Only tests set it.
var ScriptsEnabled = false

// ErrScriptsDisabled rejects a configured script while ScriptsEnabled is false.
var ErrScriptsDisabled = errors.New("Lua scripts are not supported by this Xray build")
