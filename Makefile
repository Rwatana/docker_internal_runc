PROJECT_NAME=docker_internal
IMAGE_NAME=${USER}_${PROJECT_NAME}
CONTAINER_NAME=${USER}_${PROJECT_NAME}
SHM_SIZE=2g
FORCE_RM=true

build:
	docker build \
		-f docker/Dockerfile \
		-t $(IMAGE_NAME) \
		--no-cache \
		--force-rm=$(FORCE_RM) \
		.

run:
	docker run \
		-dit \
		-v $(PWD):/usr/src \
		--name $(CONTAINER_NAME) \
		--rm \
		--cap-add ALL \
		--shm-size $(SHM_SIZE) \
		--privileged \
		$(IMAGE_NAME)

exec:
	docker exec \
		-it \
		$(CONTAINER_NAME) /bin/bash

stop:
	docker stop $(IMAGE_NAME)

restart: stop run