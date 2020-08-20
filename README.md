# Why Hashcorp vault ArangoDB plugin?
Arango DB doesn’t have plugin for HashiCorp Vault. To meet the security compliance requirement (automate password rotation), we need to develop our custom Arango plugin to support Vault.

More information: Info: https://learn.hashicorp.com/vault/developer/plugin-backends& https://www.vaultproject.io/docs/secrets/databases/custom/

# Support features
1. Access secure ArangoDB with and without TLS
2. CRUD on ArangoDB user and database.

# Installation and Compilation
```
make clean && make
```
follow this link for details to compile and install plugin:https://www.vaultproject.io/guides/operations/plugin-backends/


# Enable Arango Plugin
Assume Vault is properly configured. e.g. have plugin_dicrectory and api_addr configuration.

sample config.hcl
```
disable_mlock = true
ui=true

storage "file" {
  path = "~/vault-1/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}
plugin_directory = "/etc/vault/vault_plugins"
api_addr="http://127.0.0.1:8200"
```
After login to Vault, install with follow command. 

```
# vault secrets enable database
vault write sys/plugins/catalog/database/arango \
 sha256=338629169316ddc686b086a551c2e79de01720718cc26ce42973807d65c91396 \
 command="arango"
``` 
Need to update the sha256 value accordingly.

Now Arango plugin is ready to use for dynamic credential generation, e.g.:
```
vault write database/config/arango     plugin_name=arango     syslog_url="localhost:2514"     allowed_roles="*"     username="root"     password="root"     host="localhost"     port="8529"    http_protocol="HTTP"
vault write database/roles/pesi db_name=arango  creation_statements="pesiDB1" revocation_statements="pesiDB1" default_ttl="1m"  max_ttl="24h" 
vault read database/creds/pesi
Expected output:

Key                Value
---                -----
lease_id           database/creds/pesi/UZqI3XoeIsQxM4n9CRHIpsZ0
lease_duration     1m
lease_renewable    true
password           A1a-XODfnzxh7juI1GVQ
``` 



# Problem and solution:
## Binary is not compatible for Alpine image
```
vault write database/config/arango     plugin_name=arango     allowed_roles="*"     username="root"     password="root"     host="172.17.94.1"     port="8529"    http_protocol="HTTP"
URL: PUT https://iwo-vault-0.cwominfra.svc.cluster.local:8200/v1/sys/plugins/catalog/secret/arango
Code: 500. Errors:

* 1 error occurred:
	* could not set plugin, plugin directory is not configured
```  
Solution: start an Alpine container, install go and build the plugin. 

Key steps:
```
docker run -it  alpine:latest
apk add --update --no-cache vim git make musl-dev go curl
```
Configure Go
```
export GOPATH=/root/go
export PATH=${GOPATH}/bin:/usr/local/go/bin:$PATH
export GOBIN=$GOROOT/bin
mkdir -p ${GOPATH}/src ${GOPATH}/bin
export GO111MODULE=on
```
copy the plugin source code to the container
```
go build -o vault/plugins/arango arango-plugin/main.go
#get the binary in vault/plugins/arango
```
##  TLS  bad certificate
```
vault write database/config/arango plugin_name=arango syslog_url="192.168.1.4:2514" allowed_roles="pesi" username=
"root" password="root" host="192.168.1.4" port="8529" http_protocol="HTTP"
Error writing data to database/config/arango: Error making API request.

URL: PUT https://127.0.0.1:8200/v1/database/config/arango
Code: 400. Errors:

* error creating database object: Unrecognized remote plugin message:

This usually means that the plugin is either invalid or simply
needs to be recompiled to support the latest protocol.
```
```
Logs:
2020-04-07T01:20:12.314Z [DEBUG] secrets.database.database_17bd8843.arango: starting plugin: path=/vault/data/plugin/arango args=[/vault/data/plugin/arango]
2020-04-07T01:20:12.314Z [DEBUG] secrets.database.database_17bd8843.arango: plugin started: path=/vault/data/plugin/arango pid=22227
2020-04-07T01:20:12.314Z [DEBUG] secrets.database.database_17bd8843.arango: waiting for RPC address: path=/vault/data/plugin/arango
2020-04-07T01:20:12.440Z [INFO] http: TLS handshake error from 10.1.0.85:37410: remote error: tls: bad certificate
2020-04-07T01:20:13.651Z [INFO] http: TLS handshake error from 10.1.0.85:37430: remote error: tls: bad certificate
2020-04-07T01:20:16.368Z [INFO] http: TLS handshake error from 10.1.0.85:37476: remote error: tls: bad certificate
2020-04-07T01:20:16.369Z [ERROR] secrets.database.database_17bd8843.arango.arango: plugin tls init: error="error during token unwrap request: Put https://10.1.0.85:8200/v1/sys/wrapping/unwrap: x509: certificate is valid for 127.0.0.1, not 10.1.0.85" timestamp=2020-04-07T01:20:16.368Z
2020-04-07T01:20:16.374Z [DEBUG] secrets.database.database_17bd8843.arango: plugin process exited: path=/vault/data/plugin/arango pid=22227
```
Solution: set the skip-tls-verify to true, by modify the source code main.go to 
```
package main

import (
	"log"
	"os"
	"github.com/hashicorp/vault/api"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])
	flags.Set("tls-skip-verify", "true")
	err := arango.Run(apiClientMeta.GetTLSConfig())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
```
##  cannot allocate memory

```
vault write database/config/arango plugin_name=arango syslog_url="192.168.1.4:2514" allowed_roles="pesi" username=
"root" password="root" host="192.168.1.4" port="8529" http_protocol="HTTP"

error creating database object: Unrecognized remote plugin message: cannot allocate memory
This usually means that the plugin is either invalid or simply
needs to be recompiled to support the latest protocol
```
solution: in the vault server config, set disable_mlock = true

see https://www.vaultproject.io/docs/configuration/index.html#disable_mlock for details

##  Following error in the log
```
 vault write database/config/arango     plugin_name=arango     allowed_roles="*"     username="root"     password="root"     host="172.17.94.1"     port="8529"    http_protocol="HTTP"
```
Log:
```
transport: authentication handshake failed: tls: first record does not look like a TLS handshake
```
Solution:

The Vault environment is not healthy, there should be other error when starting up the Vault cluster. Check DNS or /etc/host file.
