### Building from sources

First of all, check `NOTES.md` if there is known issue to build smithproxy 
in your environment.

Building smithproxy from sources is simple. Just run this code:

```bash
git clone --recursive https://github.com/astibal/smithproxy
cd smithproxy
./tools/linux-deps.sh
./tools/linux-build.sh
``` 

As you certainly noticed, `tools/` directory is also where this file is located.

### Post-install tasks

It's good idea to regenerate CA certificates:
```bash
sx_regencerts
```
and start smithproxy
```bash
/etc/init.d/smithproxy start
```

### Connect to CLI and enjoy
```bash
sxy_cli
```



