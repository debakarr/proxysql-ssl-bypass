.PHONY: up-old up-new down-old down-new test logs-old logs-new status-old status-new generate-certs clean-certs

# --- Certificate Management ---
clean-certs:
	rm -f certs/*.pem certs/*.crt certs/*.key certs/*.csr certs/*.cnf

generate-certs: clean-certs
	mkdir -p certs
	@echo "Generating CA..."
	openssl req -new -x509 -nodes -days 3650 -keyout certs/ca-key.pem -out certs/ca.pem -subj "/CN=ProxySQL-CA"
	
	@echo "Generating ProxySQL Server Certificate..."
	openssl req -newkey rsa:2048 -nodes -keyout certs/proxysql-key.pem -out certs/proxysql.csr -subj "/CN=proxysql-server"
	openssl x509 -req -in certs/proxysql.csr -days 3650 -CA certs/ca.pem -CAkey certs/ca-key.pem -set_serial 01 -out certs/proxysql-cert.pem
	
	@echo "Generating Standard Client Certificate (for user_with_ssl)..."
	openssl req -newkey rsa:2048 -nodes -keyout certs/client-standard-key.pem -out certs/client-standard.csr -subj "/CN=proxysql-client-standard"
	openssl x509 -req -in certs/client-standard.csr -days 3650 -CA certs/ca.pem -CAkey certs/ca-key.pem -set_serial 02 -out certs/client-standard-cert.pem
	
	@echo "Generating SPIFFE Client Certificate (for spiffe_user)..."
	openssl req -newkey rsa:2048 -nodes -keyout certs/client-spiffe-key.pem -out certs/client-spiffe.csr -subj "/CN=proxysql-client-spiffe"
	@echo "subjectAltName=URI:spiffe://test.pytest-db-framework/ns/default/sa/client" > certs/client-ext.cnf
	openssl x509 -req -in certs/client-spiffe.csr -days 3650 -CA certs/ca.pem -CAkey certs/ca-key.pem -set_serial 03 -out certs/client-spiffe-cert.pem -extfile certs/client-ext.cnf
	
	@echo "Cleaning up certificate signing requests..."
	rm -f certs/*.csr certs/*.cnf
	@echo "Certificates generated successfully in ./certs/"

# --- ProxySQL 2.x (Old Stack) Commands ---
up-old:
	docker compose -f old-compose.yml up -d

down-old:
	docker compose -f old-compose.yml down -v

logs-old:
	docker compose -f old-compose.yml logs -f percona-mysql

status-old:
	docker compose -f old-compose.yml exec proxysql mysql -u radmin -pradmin -h 127.0.0.1 -P 6032 -e "SELECT hostgroup_id, hostname, status FROM mysql_servers;"

# --- ProxySQL 3.x (New Stack) Commands ---
up-new:
	docker compose -f new-compose.yml up -d

down-new:
	docker compose -f new-compose.yml down -v

logs-new:
	docker compose -f new-compose.yml logs -f percona-mysql

status-new:
	docker compose -f new-compose.yml exec proxysql mysql -u radmin -pradmin -h 127.0.0.1 -P 6032 -e "SELECT hostgroup_id, hostname, status FROM mysql_servers;"

# --- Test Execution ---
test:
	uv run test.py
