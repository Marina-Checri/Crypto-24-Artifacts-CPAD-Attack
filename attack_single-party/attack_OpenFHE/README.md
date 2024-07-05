# CPAD Attack on the OpenFHE Library

__Note.__ On OpenFHE version 1.1.4

__WARNING.__  If you are connecting via a VPN you may run into trouble when building the docker image.  Turn off your VPN temporarily just for this phase.  

## Building the Docker image  
Make sure to run the following command from the directory ``attack_OpenFHE``, as it contains the file ``Dockerfile``:  
``` bash
sudo docker buildx build -t attack_openfhe:0.1 .
```

## Running a container  
``` bash
sudo docker run --rm -it -v $(pwd):/attack_OpenFHE attack_openfhe:0.1 /bin/bash
```

The rest of these instructions assumes you are working within a running container.

```
cd code/
```

The root directory for this project is ``attack_OpenFHE``.

## Build


Run the following commands to link the project, build it and compile it.
```
mkdir build
cd build
cmake ..
make
```

> Note: if the repertory `build/` already exists, you may have to delete it and recreate it in the docker image.

## Running experimentations  

To launch the attack using BFV, run
```
time ./bfv_attack_exe
```
To launch the attack using BGV, run
```
time ./bgv_attack_exe
```

### Using the --no-verbose Option

You can use the `--no-verbose` option to suppress the detailed output during the execution. When this option is used, the information for each ciphertext will not be displayed.

To launch the attack using BFV without displaying detailed information for each ciphertext, run
```
time ./bfv_attack_exe --no-verbose
```

To launch the attack using BGV without displaying detailed information for each ciphertext, run
```
time ./bgv_attack_exe --no-verbose
```