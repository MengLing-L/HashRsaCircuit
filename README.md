We utilize the framework xJsnark to build the circuit for the zero-knowledge proof system in our construction.

## Our Contribution
- `HashRsaCircuit/blob/master/JsnarkCircuitBuilder/src/examples/generators/rsahash/RSAEncryptionHashCircuitGenerator.java` The circuit generation algorithm for our construction.
- `HashRsaCircuit/blob/master/JsnarkCircuitBuilder/src/examples/tests/rsahash/HashRSAEncryption_Test.java` The unit test of testing the correctness for our implementation.

## jsnark

This is a Java library for building circuits for preprocessing zk-SNARKs. The library uses libsnark as a backend (https://github.com/scipr-lab/libsnark), and can integrate circuits produced by the Pinocchio compiler (https://vc.codeplex.com/SourceControl/latest) when needed by the programmer. The code consists of two main parts:
- `JsnarkCircuitBuilder`: A Java project that has a Gadget library for building/augmenting circuits. (Check the `src/examples` package)
- `libsnark/jsnark_interface`: A C++ interface to libsnark which accepts circuits produced by either the circuit builder or by Pinocchio's compiler directly.

### Prerequisites

- Libsnark prerequisites
- JDK 8 (Higher versions are also expected to work. We've only tested with JDKs 8 and 12.)
- Junit 4
- BouncyCastle library

For Ubuntu 14.04, the following can be done to install the above:

- To install libsnark prerequisites: 

	`$ sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev`

Note: Don't clone libsnark from `https://github.com/scipr-lab/libsnark`. Make sure to use the modified libsnark submodule within the jsnark cloned repo in the next section.

- To install JDK 8: 

	`$ sudo add-apt-repository ppa:webupd8team/java`

	`$ sudo apt-get update`

	`$ sudo apt-get install oracle-java8-installer`

Verify the installed version by `java -version`. In case it is not 1.8 or later, try `$ sudo update-java-alternatives -s java-8-oracle`

- To install Junit4: 

	`$ sudo apt-get install junit4`
	
- To download BouncyCastle:

	`$ wget https://www.bouncycastle.org/download/bcprov-jdk15on-159.jar`

### Installation Instructions

- Run `$ git clone --recursive https://github.com/MengLing-L/HashRsaCircuit.git`

- Run:

	`$ cd HashRsaCircuit/libsnark`

	`$ git submodule init && git submodule update`

	`$ mkdir build && cd build && cmake ..`

	`$ make`  

The CMakeLists files were modified to produce the needed executable for the interface. The executable will appear under build/libsnark/jsnark_interface

- Compile and test the JsnarkCircuitBuilder project as in the next section..

### Running and Testing JsnarkCircuitBuilder
To compile the JsnarkCircuitBuilder project via command line, from the jsnark directory:  

    $ cd JsnarkCircuitBuilder
    $ mkdir -p bin
    $ javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar  $(find ./src/* | grep ".java$")

The classpaths of junit4 and bcprov-jdk15on-159.jar may need to be adapted in case the jars are located elsewhere. The above command assumes that  bcprov-jdk15on-159.jar was moved to the JsnarkCircuitBuilder directory.

Before running the following, make sure the `PATH_TO_LIBSNARK_EXEC` property in `config.properties` points to the path of the `run_ppzksnark` executable. 

To build the circuit of the zero-knowledge proof system in our construction, the following command can be used

    $ java -cp bin examples.generators.rsahash.RSAEncryptionHashCircuitGenerator

To run one of the JUnit tests available:

    $ java -cp bin:/usr/share/java/junit4.jar org.junit.runner.JUnitCore  examples.tests.rsahash.HashRSAEncryption_Test

Some of the examples and tests will require bcprov-jdk15on-159.jar as well to be added to the classpath.	

Note: An IDE, e.g. Eclipse, or possibly the ant tool can be used instead to build and run the Java project more conveniently.


### Writing Circuits using jsnark

To summarize the steps needed:
- Extend the `CircuitGenerator` class. 
- Override the `buildCircuit()` method: Identify the inputs, outputs and prover witness wires of your circuit, and instantiate/connect gadgets inside.
- Override the `generateSampleInput()` method: Specify how the values of the input and possibly some of the free prover witness wires are set. This helps in quick testing.
- To run a generator, the following methods should be invoked:
	- `generateCircuit()`: generates the arithmetic circuit and the constraints.
	- `evalCircuit()`: evaluates the circuit.
	- `prepFiles()`: This produces two files: `<circuit name>.arith` and `<circuit name>.in`. The first file specifies the arithemtic circuit in a way that is similar to how Pinocchio outputs arithmetic circuits, but with other kinds of instructions, like: xor, or, pack and assert. The second file outputs a file containing the values for the input and prover free witness wires. This step must be done after calling `evalCircuit()` as some witness values are computed during that step.
	- `runLibsnark()`: This runs the libsnark interface on the two files produced in the last step. By default, this method runs the r1cs_ppzksnark proof system implemented in libsnark. For other options see below.
- Note: In the executing thread, use one CircuitGenerator per thread at a time. If multiple generators are used in parallel, each needs to be in a separate thread, and the corresponding property value in config.properties need to be adapted.

#### Running circuit outputs on libsnark

Given the .arith and the .in files, it's possible to use command line directly to run the jsnark-libsnark interface. You can use the executable interface `run_ppzksnark` that appears in `jsnark/libsnark/build/libsnark/jsnark_interface` to run the libsnark algorithms on the circuit. The executable currently allows to run the proof systems `r1cs_ppzksnark` (default) and `r1cs_gg_ppzksnark` implemented in libsnark. To run the first, the executable just takes two arguments: the arithmetic circuit file path, and a sample input file path. To run the `r1cs_gg_ppzksnark` proof system [Gro16], the first argument should be `gg`, followed by the arithmetic circuit file path, and the sample input file path.

### Running circuits compiled by Pinocchio on libsnark

- To use Pinocchio directly with libsark, run the interface executable `run_ppzksnark` on the `<circuit name>.arith` and `<circuit name>.in` files. The `<circuit name>.in` should specify the hexadecimal value for each input and nizkinput wire ids, in the following format: `id value`, each on a separate line.
- It is important to assign 1 to the wire denoted as the one wire input in the arithmetic file.

### Disclaimer

The code is undergoing more testing and integration of other features. The future versions of this library will include more documentation, examples and optimizations.

### Author
This code is developed and maintained by Ahmed Kosba <akosba@cs.umd.edu>. Please email for any questions.

 
