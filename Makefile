.PHONY:
	up down psql clear

up:
	@read -p "Enter DB_USER: " db_user \
	&& read -p "Enter DB_PASSWORD: " db_password \
	&& read -p "Enter DB_NAME: " db_name \
	&& read -p "Enter API_KEY: " API_KEY \
	&& read -p "Enter TOKEN_SECRET: " token_secret \
	&& DB_USER=$$db_user DB_PASSWORD=$$db_password DB_NAME=$$db_name API_KEY=$$api_key TOKEN_SECRET=$$token_secret docker compose up -d

down:
	docker compose down \
	&& docker system prune -af \
	&& docker volume prune -f

psql:
	@read -p "Enter DB_USER: " db_user \
	&& docker compose exec -it database psql -U $$db_user
