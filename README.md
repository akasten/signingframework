# A Software Framework for Iterative Signing of Graph Data

Existing algorithms for signing graph data typically do not cover the whole signing process. In addition, they lack distinctive features such as signing graph data at different levels of granularity, iterative signing of graph data, and signing multiple graphs. This software framework implements a theoretical framework for signing arbitrary graph data provided, e.g., as RDF(S), Named Graphs, or OWL. More details on the theoretical framework are provided in a [conference paper](http://link.springer.com/chapter/10.1007/978-3-319-07443-6_11) as well in [this thesis](https://kola.opus.hbz-nrw.de/files/1393/thesis.pdf).

## Compiling

The software framework is written in Java 1.7. Compiling the framework can be done with [Apache Maven](http://maven.apache.org/) by executing the following command
```
mvn assembly:single
```
This creates the jar file `signingframework-1.0-jar-with-dependencies.jar` in the folder `target`.
This jar file includes all external Java libraries.
If this is not desired, the software framework can also be packed as a jar file without external libraries by typing

```
mvn package
```
This creates the jar file `signingframework-1.0.jar` in the folder `target`.

## Usage

The  jar file `signingframework-1.0-jar-with-dependencies.jar` can directly be executed with the command
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
The parameter `-i` specifies the file name of the input graph. Several example files can be found in the folder `examples`.
The parameter `-o` specifies the file name of the signed output graph. If the file already exists, it will be overwritten.
The parameters `-sk` and `-pk` specify the file name of the private key and public key, respectively. Both keys must be part of the same key pair. Signature keys can be created using the interactive mode of the framework.
The parameter `-c` specifies the configuration of the framework used for signing the graph.

Given a key pair consisting of the private key `my_private.key` and the public key `my_public.key`, signing the example graph `example_05.trig` with the configuration `carroll-2003` can be done with the following command:
```
java -jar target/signingframework-1.0-jar-with-dependencies.jar -i examples/example_05.trig -o signed.trig -sk my_private.key -pk my_public.key -c carroll-2003
```
