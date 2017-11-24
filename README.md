# OpenSSL FIPS Example

## How to run?

The project runs in a Docker container with OpenSSL FIPS installed. To compile and run an example, follow these steps:

```bash
$ make shell
root@container-id:~/src# make all
root@container-id:~/src# ./bin/gen-ecdsa-key
```

## Dev Environment

`make shell` runs a container with the current directory mounted, so you don't need to rebuild the container image after every change.

