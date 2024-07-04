# CPAD Attack on the Threshold BFV scheme of the Lattigo Library

__Note.__ Note that, in the paper, we performed three kind attacks on Lattigo in the threshold settings:
1/ Noise smudging deviation set to zero (which is offered by older versions of the library, up to version 4).
2/ Noise smudging deviation set to the default (small) value chosen by the library.
3/ Noise smudging deviation set to a large (lambda-independent) constant, in which we proceed by identifying noiseless LWE pairs.
Only the 2nd of these three attack paths is available in this directory, please refer to
 Sect. 4.1/Lattigo of the paper for further details.

__Note.__ On Lattigo version 5.0.2

__WARNING.__  If you are connecting via a VPN you may run into trouble when building the docker image.  Turn off your VPN temporarily just for this phase.  

## Building the Docker image  
Make sure to run the following command from the directory ``attack_threshold_lattigo``, as it contains the file ``Dockerfile``:  
``` bash
sudo docker buildx build -t attack_threshold_lattigo:0.1 .
```

## Running a container  
``` bash
sudo docker run --rm -it -v $(pwd):/attack_threshold_lattigo attack_threshold_lattigo:0.1 /bin/bash
```

The rest of these instructions assumes you are working within a running container.

```
cd code/src/
```

The root directory for this project is ``attack_threshold_lattigo``.

## Build

``` bash
go build -o bfv_threshold_attack_exe bfv_threshold_attack.go
```

# Running experimentations  

```
time ./bfv_threshold_attack_exe
```


## Modifying Lattigo lib

When constructing the Dockerfile, we install the `modified_lattigo` instead of the lattigo from the github.

### Why do we modify the lib?

We modify the lattigo library collaborative decryption function so that it works in two different modes: the normal mode where noise flooding is enabled and another mode in which it is disabled. **This second mode is not used for the attack itself**, it is only used for us to have access to the ``true'' noise of a ciphertext in order to check that the attack actually finds it correctly. 

<!--We modify the lattigo library to be able to disable the minimum noise flooding of the lattigo library.
**This modification is not used for the attack itself!** It allows us here to have access to the ``true'' noise of a ciphertext in order to check that the attack actually finds the noise.-->

### Modifications of the lib

We assume that the Lattigo library has been cloned into a directory called `Lattigo` and all commands presented below are assumed to be executed in the `Lattigo` directory.
1. Open the file `Lattigo/mhe/keyswitch_sk.go`, then
  * add an argument `without_eFresh ... bool` at the end of the argument list of the function named `NewKeySwitchProtocol`, at line 66 - this will allow us to give an optionnal boolean at this function;
  * in this function, change the lines 
    ```
    switch noise := noiseFlooding.(type) {
	case ring.DiscreteGaussian:
		eFresh := cks.params.NoiseFreshSK()
		eNoise := noise.Sigma
		eSigma := math.Sqrt(eFresh*eFresh + eNoise*eNoise)
		cks.noise = ring.DiscreteGaussian{Sigma: eSigma, Bound: 6 * eSigma}
	default:
		return cks, fmt.Errorf("invalid distribution type, expected %T but got %T", ring.DiscreteGaussian{}, noise)    }
    ```
    by
    ```
    switch noise := noiseFlooding.(type) {
	case ring.DiscreteGaussian:
		var eFresh float64
		var eNoise float64
		if len(without_eFresh) > 0 && without_eFresh[0] {
			eFresh = float64(0)
			eNoise = float64(0)
		} else {
			eFresh = cks.params.NoiseFreshSK()
			eNoise = noise.Sigma
		}
		eSigma := math.Sqrt(eFresh*eFresh + eNoise*eNoise)
		cks.noise = ring.DiscreteGaussian{Sigma: eSigma, Bound: 6 * eSigma}
	default:
		return cks, fmt.Errorf("invalid distribution type, expected %T but got %T", ring.DiscreteGaussian{}, noise)
	}
    ```
    such that if an optionnal boolean is given and this boolean is equal to `true`, the new colaborative keyswitch protocol will have a smudging variance of 0.
