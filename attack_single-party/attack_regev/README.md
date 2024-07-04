# CPAD Attack on the Regev scheme

__Note.__ Using Python version 3.10

__WARNING.__  If you are connecting via a VPN you may run into trouble when building the docker image.  Turn off your VPN temporarily just for this phase.  

## Building the Docker image  
Make sure to run the following command from the directory ``attack_regev``, as it contains the file ``Dockerfile``:  
``` bash
sudo docker buildx build -t attack_regev:0.1 .
```

## Running a container  
``` bash
sudo docker run --rm -it -v $(pwd):/attack_regev attack_regev:0.1 /bin/bash
```

The rest of these instructions assumes you are working within a running container.

```
cd code/src/
```

The root directory for this project is ``attack_regev``.


# Running experimentations  

To run the project, use
```
python3 regevcpad.py
```


## Modifying the code to use another strategy for the attack

In the file `code/src/regevcpad.py`, you can choose strategy 0 (the usual noise recovery attack) or strategy 1 (which relies only on identifying noiseless LWE-pairs, see discussion at en of Sect. 3.4 in the paper). To launch strategyX for X in {0, 1}, you just have to call `strategy=X` in the main function, at line 191.

Some comments on what these strategies are doing can be found in the file.