# CPAD Attack on the tfheLib Library

__WARNING.__  If you are connecting via a VPN you may run into trouble when building the docker image.  Turn off your VPN temporarily just for this phase.  

## Building the Docker image  
Make sure to run the following command from the directory ``attack_tfheLib``, as it contains the file ``Dockerfile``:  
``` bash
sudo docker buildx build -t attack_tfhelib:0.1 .
```

## Running a container  
``` bash
sudo docker run --rm -it -v $(pwd):/attack_tfheLib attack_tfhelib:0.1 /bin/bash
```

The rest of these instructions assumes you are working within a running container.

```
cd code/
```

The root directory for this project is ``attack_tfheLib``.

## Build


Run the following commands to build the project.
```
make
```

> Note: if the repertory `build/` already exists, you may have to delete it and recreate it in the docker image.

# Running experimentations  

To run the project, use
```
time ./bin/exe
```
