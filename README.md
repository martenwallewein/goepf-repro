# xdp_dispatcher

## Run as docker container
Build:
`docker build . -t xdp_sock:latest`

Start:
`docker run --privileged --net=host xdp_sock:latest -iface wlp2s0`
