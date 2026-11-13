PYTHON := $(if $(wildcard venv/bin/python),./venv/bin/python,python3)
THREATSIGHT := $(PYTHON) scripts/threatsight_docker.py

.PHONY: up rebuild up-tunnel rebuild-tunnel down restart logs ps ports inspect smoke test clean clean-data backup restore up-enterprise deploy

up:
	$(THREATSIGHT) up

up-enterprise:
	$(THREATSIGHT) up --enterprise

rebuild:
	$(THREATSIGHT) up --build

up-tunnel:
	$(THREATSIGHT) up --tunnel

rebuild-tunnel:
	$(THREATSIGHT) up --build --tunnel

# The full single-host live stack: all overlays, predeploy backup, build, migrate. Never use plain `make up` there.
deploy:
	$(THREATSIGHT) deploy $(ARGS)

down:
	$(THREATSIGHT) down

restart:
	$(THREATSIGHT) restart

ps:
	$(THREATSIGHT) ps

ports:
	$(THREATSIGHT) ports

inspect:
	$(THREATSIGHT) inspect

smoke:
	$(THREATSIGHT) smoke

test:
	$(THREATSIGHT) test
	$(PYTHON) -m pytest tests/test_threatsight_docker.py -q

backup:
	$(THREATSIGHT) backup

restore:
	@test -n "$(BACKUP)" || (echo "Set BACKUP=/absolute/path/to/file.dump" && exit 2)
	$(THREATSIGHT) restore "$(BACKUP)" --yes

logs:
	sudo docker compose -p threatsight logs -f --tail=100

clean:
	$(THREATSIGHT) clean --dry-run
	$(THREATSIGHT) clean

clean-data:
	$(THREATSIGHT) clean --volumes
