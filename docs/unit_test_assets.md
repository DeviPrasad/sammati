# Determining the for storing test assets
Cargo defines a bunch of environment variables for our programs to learn compile time configuration 
information. While unit testing our configuration reader (cfg.rs), we need a directory to hold sample
json files. Also, we would like to version control these unit test inputs.

The variable `CARGO_MANIFEST_DIR` represents the path of the crate root (where Cargo.toml lives). We use
this to identify the location of the unit test inputs. The following line of code is used in unit tests
to process configuration information stored in json (see `test_002` in cfg.rs):

```
let pb: PathBuf = [env!("CARGO_MANIFEST_DIR"), "mock", "config", "fip-cfg.json"].iter().collect();
```
