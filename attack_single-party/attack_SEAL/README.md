# CPAD Attack on the SEAL Library

__Note.__ On SEAL version 4.1

__WARNING.__  If you are connecting via a VPN you may run into trouble when building the docker image.  Turn off your VPN temporarily just for this phase.  

## Building the Docker image  
Make sure to run the following command from the directory ``attack_SEAL``, as it contains the file ``Dockerfile``:  
``` bash
sudo docker build -t attack_seal:0.1 .
```

## Running a container  
``` bash
sudo docker run --rm -it -v $(pwd):/attack_SEAL attack_seal:0.1 /bin/bash
```

The rest of these instructions assumes you are working within a running container.

```
cd code/
```

The root directory for this project is ``attack_SEAL``.

## Build


Run the following commands to link the project, build it and compile it.
```
cmake -S . -B build
cmake --build build
```

> Note: if the repertory `build/` already exists, you may have to delete it and recreate it in the docker image.

# Running experimentations  

To launch the attack using BFV, run
```
time ./build/bin/attack_bfv_exe
```

To launch the attack using BGV, run
```
time ./build/bin/attack_bgv_exe
```

## Modifying SEAL lib and re-build it

When constructing the Dockerfile, we install the `modified_SEAL` instead of the SEAL from the github.

### Why do we modify the lib?
To check that our attack works, we instrumented the library to display the true noise of the ciphertexts. To do so, we modify the SEAL library to access (make public) the variables (normally private) context_ and pool_ as well as the dot_product_ct_sk_array() function.
**This modification is not used for the attack itself!** It allows us here to have access to the noise of a ciphertext (a forbidden action) in order to check that the attack actually duly finds it.

This modification is only used to execute the function `bfv_get_secret_noise` in our code, to verify that the attack correctly recover the noise of a ciphertext.

### Modifications of the lib

We assume that Microsoft SEAL has been cloned into a directory called `SEAL` and all commands presented below are assumed to be executed in the directory `SEAL`.
1. Open the file `SEAL/native/src/seal/decryptor.h`, then
  * in `SEAL/native/src/seal/decryptor.h`, at line 128, add ```/***/ private: /***/```; 
  * in `SEAL/native/src/seal/decryptor.h`, at line 118, add ```/***/ public: /***/```;
  * such that the function `dot_product_ct_sk_array` and the variables `pool_` and `context_` are public.
2. Save the modifications in `SEAL/native/src/seal/decryptor.h`.
3. From the cloned directory `SEAL`, reinstall and re-build Microsoft SEAL as previously.
  * *If you have root access to the system you can install it globally with the following commands.*
	```PowerShell
	  cmake -S . -B build
	  cmake --build build
	  sudo cmake --install build
	  ```

## Modifying the code to use another strategy for the attack

In the file `src/main.cpp`, you can choose strategy 0 (the usual noise recovery attack) or strategy 1 (which relies only on identifying noiseless LWE-pairs, see discussion at en of Sect. 3.4 in the paper). To launch strategyX for X in {0, 1}, you just have to call `strategyX();` in the main function.

After the modification, you need to compile (`cmake --build build`) and launch (`time ./build/bin/attack_exe`) the attack.

Some comments on what these strategies are doing can be found in the include and/or source files.
