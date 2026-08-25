package stat

import (
	"net"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/stats"
)

type Connection interface {
	net.Conn
}

type CounterConnection struct {
	Connection
	ReadCounter  stats.Counter
	WriteCounter stats.Counter
}

func (c *CounterConnection) Read(b []byte) (int, error) {
	nBytes, err := c.Connection.Read(b)
	if c.ReadCounter != nil {
		c.ReadCounter.Add(int64(nBytes))
	}

	return nBytes, err
}

func (c *CounterConnection) Write(b []byte) (int, error) {
	nBytes, err := c.Connection.Write(b)
	if c.WriteCounter != nil {
		c.WriteCounter.Add(int64(nBytes))
	}
	return nBytes, err
}

func TryUnwrapStatsConn(conn net.Conn) net.Conn {
	if conn == nil {
		return conn
	}
	if conn, ok := conn.(*CounterConnection); ok {
		return corenet.UnwrapPhysicalPeer(conn.Connection)
	}
	return corenet.UnwrapPhysicalPeer(conn)
}

// TryCloseWrite propagates a TCP-style half-close through statistics and
// physical-peer wrappers. Connections without half-close support are left open.
func TryCloseWrite(conn net.Conn) error {
	if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	unwrapped := TryUnwrapStatsConn(conn)
	if closeWriter, ok := unwrapped.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}
