## Global Safe Module

**The Global module allows Safe to go with a sign once deploy on multiple chains approach.**

A Safe usually has replay attack prevention built in, the Global module removes this protection as we want to be execute the same transactions on all chains without having to sign multiple times. This module is targeted at projects that are using deterministic deployments on multiple chains.


## Development

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

## Deployments

https://github.com/citrus-finance/citrus-deployments