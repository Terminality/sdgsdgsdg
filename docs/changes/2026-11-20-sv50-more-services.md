# SV-50: RabbitMQ, Home Assistant, Docker and containers

- New services: RabbitMQ (5672; the management page on 15672 is shown),
  Home Assistant (8123, HTTP), the Docker service.
- Docker or Podman containers: a new question (Enter = yes; --no-containers,
  or "containers" in --services).  A stopped container is shown with its log
  and starting it is asked (default no when it ended with exit 0); a paused one
  is unpaused; one restarting over and over is shown only.  Checked after,
  undo stops it again.  New --fix kind: container.
