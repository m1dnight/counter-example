# Counter App 

## Building Compliace Circuit 

To build the compliance circuit, Risc0 needs to generate the bin file and the id.

This will take a while.

```shell 
cargo risczero build --manifest-path deps/counter_logic_circuit/counter_methods/counter_guest/Cargo.toml
```

The output should resemble something like the following:

```text 
ELFs ready at:
ImageID: biglongvaluehere - /Users/.../counter_guest.bin
```

Copy the counter_guest.bin file to 