# A Software Framework for Iterative Signing of Graph Data

Existing algorithms for signing graph data typically do not cover the whole signing process. In addition, they lack distinctive features such as signing graph data at different levels of granularity, iterative signing of graph data, and signing multiple graphs.
This software framework implements a [theoretical framework](http://icp.it-risk.iwvi.uni-koblenz.de/wiki/Signing_Graphs) for signing arbitrary graph data provided, e.g., as RDF(S), Named Graphs, or OWL. More details on the theoretical framework are provided at an [external site](http://icp.it-risk.iwvi.uni-koblenz.de/wiki/Signing_Graphs).

## Compiling

Compiling the software framework can be done using [Apache Maven](http://maven.apache.org/). Executing the following command

```
mvn assembly:single
```
creates the jar file `signingframework-1.0-jar-with-dependencies.jar` located in the folder `target`.
This jar file includes all external Java libraries.
If this is not desired, the software framework can also be packed as a jar file without external libraries by typing

```
mvn package
```
This creates the jar file `signingframework-1.0.jar` in the folder `target`.

## Usage

The  jar `signingframework-1.0-jar-with-dependencies.jar` file can directly be executed with the command
```
java -jar target/signingframework-1.0-jar-with-dependencies.jar
```
This will start the interactive mode of the signing framework which supports signing of graphs and creating signature keys.
Additionally, the framework also supports a non-interactive mode. This mode only allows for signing graphs. Using this mode requires specification of the following parameters in arbitrary order:
```
 -i  input graph
 -o  output graph
 -sk file name of secret (private) key 
 -pk file name of public key 
 -c  framework configuration
     possible values:
       carroll-2003
       fisteus-2010
       sayers-2004
       tummarello-2005
```
The parameter `-i` specifies the file name of the input graph. Several example files can be found at the folder `examples`.
The parameter `-o` specifies the file name of the signed output graph. If file already exists, it will be overwritten.
The parameters `-sk` and `-pk` specify the file name of the private key and public key, respectively. Both keys must be part of the same key pair. Signature keys can be created using the interactive mode of the framework.
The parameter `-c` specifies the configuration of the framework used for signing the graph. Detailed information about these functions are provided at an [external web site](http://icp.it-risk.iwvi.uni-koblenz.de/wiki/Graph_Signing_Functions).

Given a key pair consisting of the private key `my_private.key` and the public key `my_public.key`, signing the example graph `example_05.trig` with the configuration `carroll-2003` can be achieved using the following command:
```
java -jar target/signingframework-1.0-jar-with-dependencies.jar -i examples/example_05.trig -o signed.trig -sk my_private.key -pk my_public.key -c carroll-2003
```
