package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	mysqlplugin "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// MySQLClient is a client for MySQL database.
//
// Internally client uses go-sql-driver/mysql driver.
type MySQLClient struct{}

// IsMySQL checks if the given host is running MySQL database.
//
// If the host is running MySQL database, it returns true.
// If the host is not running MySQL database, it returns false.
func (c *MySQLClient) IsMySQL(host string, port int) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	plugin := &mysqlplugin.MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	if service == nil {
		return false, nil
	}
	return true, nil
}

// Connect connects to MySQL database using given credentials.
//
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// The connection is closed after the function returns.
func (c *MySQLClient) Connect(host string, port int, username, password string) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	dsn, err := BuildDSN(DSNOptions{
		Host:     host,
		Port:     port,
		DbName:   "INFORMATION_SCHEMA",
		Protocol: "tcp",
		Username: username,
		Password: password,
	})
	if err != nil {
		return false, err
	}
	return connectWithDSN(dsn)
}

type MySQLInfo struct {
	Host      string               `json:"host,omitempty"`
	IP        string               `json:"ip"`
	Port      int                  `json:"port"`
	Protocol  string               `json:"protocol"`
	TLS       bool                 `json:"tls"`
	Transport string               `json:"transport"`
	Version   string               `json:"version,omitempty"`
	Debug     plugins.ServiceMySQL `json:"debug,omitempty"`
	Raw       string               `json:"metadata"`
}

// returns MySQLInfo when fingerpint is successful
func (c *MySQLClient) FingerprintMySQL(host string, port int) (MySQLInfo, error) {
	info := MySQLInfo{}
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return info, protocolstate.ErrHostDenied.Msgf(host)
	}
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return info, err
	}
	defer conn.Close()

	plugin := &mysqlplugin.MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return info, err
	}
	if service == nil {
		return info, fmt.Errorf("something went wrong got null output")
	}
	// fill all fields
	info.Host = service.Host
	info.IP = service.IP
	info.Port = service.Port
	info.Protocol = service.Protocol
	info.TLS = service.TLS
	info.Transport = service.Transport
	info.Version = service.Version
	info.Debug = service.Metadata().(plugins.ServiceMySQL)
	bin, _ := service.Raw.MarshalJSON()
	info.Raw = string(bin)
	return info, nil
}

// ConnectWithDSN connects to MySQL database using given DSN.
// we override mysql dialer with fastdialer so it respects network policy
func (c *MySQLClient) ConnectWithDSN(dsn string) (bool, error) {
	return connectWithDSN(dsn)
}

func (c *MySQLClient) ExecuteQueryWithOpts(opts DSNOptions, query string) (*utils.SQLResult, error) {
	if !protocolstate.IsHostAllowed(opts.Host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}
	dsn, err := BuildDSN(opts)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}

	data, err := utils.UnmarshalSQLRows(rows)
	if err != nil {
		if len(data.Rows) > 0 {
			// allow partial results
			return data, nil
		}
		return nil, err
	}
	return data, nil
}

// ExecuteQuery connects to Mysql database using given credentials and database name.
// and executes a query on the db.
func (c *MySQLClient) ExecuteQuery(host string, port int, username, password, dbName, query string) (*utils.SQLResult, error) {
	return c.ExecuteQueryWithOpts(DSNOptions{
		Host:     host,
		Port:     port,
		DbName:   dbName,
		Protocol: "tcp",
		Username: username,
		Password: password,
	}, query)
}

func init() {
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
}
