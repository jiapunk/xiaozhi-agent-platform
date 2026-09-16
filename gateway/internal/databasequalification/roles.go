package databasequalification

import "fmt"

type Role string

const (
	RoleOwnership            Role = "ownership"
	RoleAccountAuthorization Role = "accountauthorization"
	RoleFactoryTimeAuthority Role = "factorytimeauthority"
)

var ExactRoles = []Role{
	RoleOwnership,
	RoleAccountAuthorization,
	RoleFactoryTimeAuthority,
}

func (role Role) Valid() bool {
	return role == RoleOwnership || role == RoleAccountAuthorization ||
		role == RoleFactoryTimeAuthority
}

func equalRoles(roles []Role) bool {
	if len(roles) != len(ExactRoles) {
		return false
	}
	for index := range roles {
		if roles[index] != ExactRoles[index] {
			return false
		}
	}
	return true
}

func roleSchemaChecks(role Role) ([]schemaCheck, error) {
	switch role {
	case RoleOwnership:
		return []schemaCheck{
			{"xz_ownership_schema", 3, "xz-owner-v3-20260809-lifecycle"},
			{"xz_action_consent_schema", 1, "xz-action-consent-db-v1-20260810"},
			{"xz_action_consent_wake_schema", 1, "xz-action-consent-wake-db-v1-20260810"},
		}, nil
	case RoleAccountAuthorization:
		return []schemaCheck{
			{"xz_companion_authorization_schema", 1, "xz-companion-auth-db-v1-20260810"},
			{"xz_companion_push_schema", 1, "xz-companion-push-db-v1-20260810"},
			{"xz_service_entitlement_schema", 1, "xz-service-entitlement-db-v1-20260811"},
		}, nil
	case RoleFactoryTimeAuthority:
		return []schemaCheck{
			{"xz_factory_time_schema", 1, "xz-factory-time-db-v1-20260810"},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported managed database role")
	}
}

type schemaCheck struct {
	table    string
	version  int
	contract string
}
