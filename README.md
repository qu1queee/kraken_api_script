## Kraken API ruby script (WIP)

An script that makes use of the [Kraken API documentation](https://www.kraken.com/help/api) for trading purposes.

This script, is based on the official Kraken ruby API repository, see [leishman/kraken_ruby](https://github.com/leishman/kraken_ruby) and it´s intended to be use as a standalone script.

## Generate the API Key
In your Kraken account , navigate to **Settings** >> **API**, and generate a new key. Adjust the key permissions according to your needs.

This will generate two keys, an `api key` and `private key`.


## Usage
1. Make sure the script is executable, otherwise
```
chmod +x kraken_api.rb
```
2. Run it to see how to use it.

 ```
 ./kraken_api.rb --help
 kraken_api interacts with the Kraken API
 Find more information at https://www.kraken.com/help/api

 Main commands are:
    TradeBalance           get your current Trade Balance
    Balance                get cour current Balance
    Ticker                 get a ticker information
    Assets                 get an asset information
    AssetPairs             get an asset pair information
    Trades                 get trades
    OHLC                   get ohlc data
    TradingMode            run automatic trading
 See './kraken_api.rb COMMAND --help' for more information on a specific command.
 ```

3. Take a look at each command option, for example:
```
./kraken_api.rb TradeBalance -h
Usage: TradeBalance [api-key] [private-key] [input]
    -a, --api-key value              api-key (mandatory)
    -p, --private-key value          api-private-key (mandatory)
    -i, --method-input parameters    eg. asset:ZEUR (optional)
```

## TODO
- Support all methods from the API into the script
- enable/disable debug mode
- Usage of OHLC data in Trading Mode, to make decisions of selling smarter
- Output of the request should be available in different formats(e.g. json, etc)
