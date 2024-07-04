# CPAD Attack on the Threshold BFV scheme of the OpenFHE Library

__Note.__ On OpenFHE version 1.1.4

__WARNING.__  If you are connecting via a VPN you may run into trouble when building the docker image.  Turn off your VPN temporarily just for this phase.  

## Building the Docker image  
Make sure to run the following command from the directory ``attack_threshold_OpenFHE``, as it contains the file ``Dockerfile``:  
``` bash
sudo docker buildx build -t attack_threshold_openfhe:0.1 .
```

## Running a container  
``` bash
sudo docker run --rm -it -v $(pwd):/attack_threshold_OpenFHE attack_threshold_openfhe:0.1 /bin/bash
```

The rest of these instructions assumes you are working within a running container.

```
cd code/
```

The root directory for this project is ``attack_threshold_OpenFHE``.

## Build

Run the following commands to link the project, build it and compile it.
```
mkdir build
cd build
cmake ..
make
```

> Note: if the repertory `build/` already exists, you may have to delete it and recreate it in the docker image.

# Running experimentations  

To launch the attack using ThHE BFV, run
```
time ./bfv_threshold_attack_exe
```


## Modifying OpenFHE lib

When constructing the Dockerfile, we install the `modified_openfhe` instead of the OpenFHE from the github.

### Why do we modify the lib?

We modify the OpenFHE library partial decryption functions so that it works in two different modes: the normal mode where noise flooding is enabled and another mode in which it is disabled. **This second mode is not used for the attack itself**, it is only used for us to have access to the "true" noise of a ciphertext in order to check that the attack actually finds it correctly. 

<!-- We modify the library to be able to disable the minimum noise flooding of the lattigo library.
**This modification is not used for the attack itself!** It allows us here to have access to the ``true'' noise of a ciphertext in order to check that the attack actually finds the noise.
-->

### Modifications of the lib

We assume that the OpenFHE library has been cloned into a directory called `openfhe` and all commands presented below are assumed to be executed in the `openfhe` directory.

1. We added an extra boolean parameter `disable_noise_flooding` set by default to false in the `MultipartyDecryptLead` and `MultipartyDecryptLead` functions and all their overloads.
2. More specifically, the changes on the overloads and declarations are:
  * openfhe/src/pke/include/cryptocontext.h - add the parameter `bool disable_noise_flooding=false` set by default to false l.2825 and 2846, and give it as an argument to the functions l.2831 and 2852.
  * openfhe/src/pke/include/schemebase/base-multiparty.h - add the parameter `bool disable_noise_flooding=false` set by default to false l.188, 198
  * openfhe/src/pke/include/schemebase/base-scheme.h - add the parameter `bool disable_noise_flooding=false` set by default to false l.1279, 1282
  * openfhe/src/pke/include/schemerns/rns-multiparty.h - add the parameter `bool disable_noise_flooding=false` set by default to false l.84, 87
  * openfhe/src/pke/lib/schemebase/base-scheme.cpp - add the parameter `bool disable_noise_flooding` l.226 and 236, and give it as an argument to the functions l.230 and 241
  3. Open and modify the file:
  * `openfhe/src/pke/lib/schemebase/base-multiparty.cpp`:
      1. add the parameter `bool disable_noise_flooding` l.225 and 255
      2. l. 239 and 268, add a condition on this boolean: if it is set to true, do not add an additional flooding noise, otherwise, run the normal mode (the code does not change). Thus the modified code is , respectively in l.239 and 268:
      ```
      Element b;
      if(disable_noise_flooding){
        b = cv[0] + s * cv[1];
      }else{
        b = cv[0] + s * cv[1] + ns * e;
      }
      ```
      and
      ```
      Element b;
      if(disable_noise_flooding){
        b = s * cv[1];
      }else{
        b = s * cv[1] + es * e;
      }
      ```

  * openfhe/src/pke/lib/schemerns/rns-multiparty.cpp:
      1. add the parameter `bool disable_noise_flooding` l.41 and 121
      2. l. 98 and 173, add a condition on this boolean: if it is set to true, do not add an additional flooding noise, otherwise, run the normal mode (the code does not change). Thus the modified code is , respectively in l.98 and 173:
      ```
      DCRTPoly b;
      if(disable_noise_flooding){
        b = cv[0] + s * cv[1];
      }else{
        b = cv[0] + s * cv[1] + ns * noise;
      }
      ```
      and
      ```
      DCRTPoly b;
      if(disable_noise_flooding){
        b = s * cv[1];
      }else{
        b = s * cv[1] + ns * noise;
      }
      ```
