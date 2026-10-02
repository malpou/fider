package entity_test

import (
	"encoding/json"
	"testing"

	"github.com/getfider/fider/app/models/entity"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/env"
)

func TestOAuthConfig_MarshalJSON_ClientSecretFromEnv(t *testing.T) {
	testCases := []struct {
		name     string
		envID    string
		envSec   string
		expected bool
	}{
		{"matching client id", "CU_CL_ID", "ENV_SECRET_VALUE", true},
		{"other client id", "OTHER_ID", "ENV_SECRET_VALUE", false},
		{"unset", "", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			RegisterT(t)
			original := env.Config.OAuth.Custom
			env.Config.OAuth.Custom.ClientID = tc.envID
			env.Config.OAuth.Custom.Secret = tc.envSec
			t.Cleanup(func() { env.Config.OAuth.Custom = original })

			config := entity.OAuthConfig{ClientID: "CU_CL_ID", ClientSecret: "STORED_SECRET_VALUE"}
			bytes, err := json.Marshal(config)
			Expect(err).IsNil()

			var out map[string]any
			Expect(json.Unmarshal(bytes, &out)).IsNil()
			Expect(out["clientSecretFromEnv"]).Equals(tc.expected)
			// The masked secret always comes from the stored value.
			Expect(out["clientSecret"]).Equals("STO...LUE")
		})
	}
}
