.PHONY: build push help

CONTAINER_CLI ?= podman
REGISTRY ?= docker.io
IMAGE_NAME ?= gr00vysky/knock2spot
IMAGE_TAG ?= latest
IMAGE := $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

help:
	@echo "Available targets:"
	@echo "  make build          - Build the container image"
	@echo "  make push           - Push the container image to registry"
	@echo "  make build-push     - Build and push the container image"
	@echo "  make help           - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  CONTAINER_CLI       - Container CLI tool (default: $(CONTAINER_CLI))"
	@echo "  REGISTRY            - Container registry (default: $(REGISTRY))"
	@echo "  IMAGE_NAME          - Image name (default: $(IMAGE_NAME))"
	@echo "  IMAGE_TAG           - Image tag (default: $(IMAGE_TAG))"
	@echo "  IMAGE               - Full image path: $(IMAGE)"

build:
	@echo "Building container image: $(IMAGE)"
	$(CONTAINER_CLI) build -t $(IMAGE) .

push:
	@echo "Pushing container image: $(IMAGE)"
	$(CONTAINER_CLI) push $(IMAGE)

build-push: build push
	@echo "Successfully built and pushed: $(IMAGE)"
