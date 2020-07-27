package vault_tools

import (
	"crypto/tls"
	"errors"
	"github.com/hashicorp/vault/api"
	"net/http"
	"os"
	"strings"
)

const EnvVaultAddress = "VAULT_ADDR"
const EnvVaultToken = "VAULT_TOKEN"
const EnvVaultPath = "VAULT_PATH"

func LoadEnvProperties(ignoreSSL bool) (map[string]interface{}, error) {
	address := os.Getenv(EnvVaultAddress)
	token := os.Getenv(EnvVaultToken)
	vaultPath := os.Getenv(EnvVaultPath)
	return LoadProperties(ignoreSSL, vaultPath, address, token)
}

func LoadProperties(ignoreSSL bool, vaultPath string, address string, token string) (map[string]interface{}, error) {
	cbe := "cannot be empty"
	if len(vaultPath) == 0 {
		return nil, errors.New(strings.Join([]string{"vault path", cbe}, " "))
	}
	if len(address) == 0 {
		return nil, errors.New(strings.Join([]string{"vault path", cbe}, " "))
	}
	if len(token) == 0 {
		return nil, errors.New(strings.Join([]string{"vault token", cbe}, " "))
	}

	if ignoreSSL {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client, err := api.NewClient(&api.Config{
		Address: address,
	})
	client.SetToken(token)
	if err != nil {
		return nil, err
	}

	secretValues, err := client.Logical().Read(vaultPath)
	if err != nil {
		return nil, err
	}

	if secretValues.Data == nil {
		return nil, errors.New("no secrets in vault")
	}

	return secretValues.Data, err
}
