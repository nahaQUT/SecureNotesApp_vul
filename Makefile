.DEFAULT_GOAL := build

build:
	@sudo docker build -t secure_notes -f Dockerfile .

run:
	@sudo docker run -p 5001:5001 --rm secure_notes

clean:
	@sudo docker container prune
