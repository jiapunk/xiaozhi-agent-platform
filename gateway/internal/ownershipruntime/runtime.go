package ownershipruntime

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
)

type Runtime struct {
	Resolver         *deviceclaim.PostgresResolver
	Database         *sql.DB
	OperationTimeout time.Duration
}

func OpenFromEnvironment(allowInsecure bool) (*Runtime, error) {
	databaseURL := os.Getenv("OWNERSHIP_DATABASE_URL")
	if err := validateURL(databaseURL, allowInsecure); err != nil {
		return nil, err
	}
	maximum, err := integer("OWNERSHIP_DATABASE_MAX_CONNECTIONS", 20, 2, 200)
	if err != nil {
		return nil, err
	}
	idle, err := integer("OWNERSHIP_DATABASE_IDLE_CONNECTIONS", 5, 0, maximum)
	if err != nil {
		return nil, err
	}
	ttlSeconds, err := integer("OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS",
		300, 30, 3600)
	if err != nil {
		return nil, err
	}
	timeoutMS, err := integer("OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS",
		2000, 100, 30000)
	if err != nil {
		return nil, err
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open ownership database: %w", err)
	}
	database.SetMaxOpenConns(maximum)
	database.SetMaxIdleConns(idle)
	database.SetConnMaxLifetime(time.Duration(ttlSeconds) * time.Second)
	resolver, err := deviceclaim.NewPostgresResolver(database,
		time.Duration(timeoutMS)*time.Millisecond)
	if err == nil {
		err = resolver.VerifySchema()
	}
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	return &Runtime{Resolver: resolver, Database: database,
		OperationTimeout: time.Duration(timeoutMS) * time.Millisecond}, nil
}

func (runtime *Runtime) Close() error {
	if runtime == nil || runtime.Database == nil {
		return nil
	}
	return runtime.Database.Close()
}

func validateURL(value string, allowInsecure bool) error {
	endpoint, err := url.Parse(value)
	if value == "" || err != nil || (endpoint.Scheme != "postgres" &&
		endpoint.Scheme != "postgresql") || endpoint.Host == "" ||
		endpoint.Path == "" || endpoint.Path == "/" || endpoint.Fragment != "" {
		return fmt.Errorf("OWNERSHIP_DATABASE_URL must be an absolute PostgreSQL database URL")
	}
	sslModes := endpoint.Query()["sslmode"]
	if len(sslModes) > 1 {
		return fmt.Errorf("OWNERSHIP_DATABASE_URL must contain at most one sslmode")
	}
	if !allowInsecure && (len(sslModes) != 1 || sslModes[0] != "verify-full") {
		return fmt.Errorf("OWNERSHIP_DATABASE_URL must use sslmode=verify-full outside development")
	}
	return nil
}

func integer(name string, fallback, minimum, maximum int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer from %d through %d",
			name, minimum, maximum)
	}
	return parsed, nil
}
