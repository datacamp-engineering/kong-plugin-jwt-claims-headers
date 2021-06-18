.PHONY: start
start:
	docker compose -f docker-compose-test.yml up --build

.PHONY: stop
stop:
	docker compose -f docker-compose-test.yml down

.PHONY: test
test:
	docker compose exec kong /docker-entrypoint.sh kong test

.PHONY: demo
demo:
	docker compose down
	docker compose up
