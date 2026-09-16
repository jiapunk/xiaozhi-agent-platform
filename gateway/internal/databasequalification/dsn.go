package databasequalification

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func OpenStore(databaseURL string, role Role,
	operationTimeout time.Duration) (*Store, error) {
	if !validManagedDatabaseURL(databaseURL) || !role.Valid() ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 10*time.Second {
		return nil, fmt.Errorf("managed database qualification connection is invalid")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open managed database qualification connection")
	}
	database.SetMaxOpenConns(2)
	database.SetMaxIdleConns(2)
	database.SetConnMaxIdleTime(15 * time.Second)
	database.SetConnMaxLifetime(30 * time.Second)
	store, err := NewStore(database, role, operationTimeout)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	return store, nil
}

func validManagedDatabaseURL(value string) bool {
	if len(value) < 16 || len(value) > 8*1024 ||
		strings.ContainsAny(value, "\r\n\t") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" &&
		parsed.Scheme != "postgresql") || parsed.User == nil ||
		parsed.Host == "" || parsed.Path == "" || parsed.Path == "/" ||
		parsed.Fragment != "" || parsed.RawFragment != "" {
		return false
	}
	host := parsed.Hostname()
	if host == "" || strings.EqualFold(host, "localhost") {
		return false
	}
	if address := net.ParseIP(host); address != nil &&
		(address.IsLoopback() || address.IsUnspecified() ||
			address.IsLinkLocalUnicast() || address.IsMulticast()) {
		return false
	}
	query := parsed.Query()
	if query.Get("sslmode") != "verify-full" || len(query["sslmode"]) != 1 {
		return false
	}
	for key := range query {
		if key == "sslmode" || key == "sslrootcert" || key == "connect_timeout" ||
			key == "application_name" {
			continue
		}
		return false
	}
	for _, key := range []string{"sslrootcert", "connect_timeout",
		"application_name"} {
		if len(query[key]) > 1 {
			return false
		}
	}
	if root := query.Get("sslrootcert"); root != "" &&
		(!filepath.IsAbs(root) || len(root) > 4096) {
		return false
	}
	if rawTimeout := query.Get("connect_timeout"); rawTimeout != "" {
		timeout, err := strconv.Atoi(rawTimeout)
		if err != nil || timeout < 1 || timeout > 30 ||
			strconv.Itoa(timeout) != rawTimeout {
			return false
		}
	}
	if application := query.Get("application_name"); application != "" &&
		(len(application) > 64 || strings.ContainsAny(application, " \r\n\t")) {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return false
		}
	}
	return true
}
