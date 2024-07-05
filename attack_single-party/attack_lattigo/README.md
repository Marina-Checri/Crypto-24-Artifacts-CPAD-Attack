# CPAD Attack on the Lattigo Library

__Note.__ On Lattigo version 5.0.2

__WARNING.__  If you are connecting via a VPN you may run into trouble when building the docker image.  Turn off your VPN temporarily just for this phase.  

## Building the Docker image  
Make sure to run the following command from the directory ``attack_lattigo``, as it contains the file ``Dockerfile``:  
``` bash
sudo docker buildx build -t attack_lattigo:0.1 .
```

## Running a container  
``` bash
sudo docker run --rm -it -v $(pwd):/attack_lattigo attack_lattigo:0.1 /bin/bash
```

The rest of these instructions assumes you are working within a running container.

```
cd code/src/
```

The root directory for this project is ``attack_lattigo``.

## Build

```
go build -o bfv_attack bfv_attack.go
```

## Running experimentations  

```
time ./bfv_attack
```

### Using the --no-verbose Option

You can use the `--no-verbose` option to suppress the detailed output during the execution. When this option is used, the information for each ciphertext will not be displayed.

To launch the attack without displaying detailed information for each ciphertext, run
```
time ./bfv_attack --no-verbose
```

## Modifying the code to use another strategy for the attack

<!-- In the file src/main.cpp, you can choose strategy 0 (the usual noise recovery attack) or strategy 1 (which relies only on identifying noiseless LWE-pairs, see discussion at en of Sect. 3.4 in the paper). To launch strategyX for X in {0, 1}, you just have to call strategyX(); in the main function.-->

<!-- In the file `code/src/bfv_attack.go`, you can choose strategy 0, strategy 1 or strategy 2. To launch strategyX for X in {0, 1, 2}, you just have to call `strategyX();` in the main function.-->


In the file `code/src/bfv_attack.go`, you can choose strategy 0 (the usual noise recovery attack) or strategy 1 (which relies only on identifying noiseless LWE-pairs, see discussion at en of Sect. 3.4 in the paper) or strategy 2 (adapted noise recovery attack for larger parameters see discussion in Sect. 4.1/Lattigo on p. 13). To launch strategyX for X in {0, 1, 2}, you just have to call `strategyX();` in the main function.

After the modification, you need to compile (`go build -o bfv_attack bfv_attack.go`) and launch (`time ./bfv_attack`) the attack.

Some comments on what these strategies are doing can be found in the file.
