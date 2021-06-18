.PHONY: start-tests
start-tests:
	docker compose -f docker-compose-test.yml up

.PHONY: test
test:
	docker compose restart kong

.PHONY: demo
demo:
	docker compose down
	docker compose up
