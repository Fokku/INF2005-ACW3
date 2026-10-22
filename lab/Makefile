# INF2005 ACW3 - lab helpers.  Run from the lab/ directory.
# `docker compose` (v2) is assumed; swap to `docker-compose` if you run v1.
DC = docker compose

.PHONY: help build up down verify verify-patched logs attacker remediation clean

help:
	@echo "make build        - build target(2.4.68), backend, attacker images"
	@echo "make up           - build + start the vulnerable lab (detached)"
	@echo "make verify       - confirm each vuln is present & reachable (:8080)"
	@echo "make remediation  - also start the patched target (2.4.69, :8081)"
	@echo "make verify-patched - run checks against the patched target"
	@echo "make attacker     - shell into the Kali attacker box"
	@echo "make logs         - follow the target's httpd logs"
	@echo "make down / clean - stop / stop and remove images+volumes"

build:
	$(DC) build

up:
	$(DC) up -d --build
	@echo "Target:  http://127.0.0.1:8080/   (run 'make verify')"

verify:
	./scripts/verify.sh

remediation:
	$(DC) --profile remediation up -d --build
	@echo "Patched target: http://127.0.0.1:8081/"

verify-patched:
	TARGET=http://127.0.0.1:8081 CONTAINER=acw3-target-patched EXPECT_VERSION=2.4.69 ./scripts/verify.sh

attacker:
	$(DC) exec attacker bash

logs:
	$(DC) logs -f target

down:
	$(DC) --profile remediation down

clean:
	$(DC) --profile remediation down --rmi local -v
