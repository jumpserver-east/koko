variable "TAG" {
  default = "dev"
}
target "ce" {
  context    = "./source"
  dockerfile = "Dockerfile"
  args = {
    VERSION = "${TAG}"
  }
  cache-from = ["type=gha,scope=koko-ce"]
  cache-to   = ["type=gha,mode=max,scope=koko-ce"]
}

target "ee" {
  context    = "./source"
  dockerfile = "Dockerfile-ee"
  args = {
    VERSION = "${TAG}"
  }
  contexts = {
    "jumpserver/koko:${TAG}-ce" = "target:ce"
  }
  tags = ["ghcr.io/jumpserver-east/koko:${TAG}"]
  labels = {
    "org.opencontainers.image.version" = "${TAG}"
    "org.jumpserver.edition"           = "ee"
  }
  cache-from = ["type=gha,scope=koko-ee"]
  cache-to   = ["type=gha,mode=max,scope=koko-ee"]
}
