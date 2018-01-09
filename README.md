## Kraken API ruby script (WIP)

This is a ruby executable script that makes use of the [Kraken API documentation](https://www.kraken.com/help/api) for trading purposes.

The script is based on the official Kraken ruby API repository, see [leishman/kraken_ruby](https://github.com/leishman/kraken_ruby) and it´s intended to be use as a standalone script.

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
./kraken_api.rb
This script interacts with the Kraken API, use it as follows:
    -a, --api-key value              api-key (mandatory)
    -p, --private-key value          api-private-key (mandatory)
    -m, --method name                more info at https://www.kraken.com/help/api (default: TradeBalance())
    -i, --method-input parameters    eg. asset:ZEUR (optional)
```

3. Provide the mandatory arguments. The `api_key` and the `private_key`.

4. **OPTIONAL argument**. Set the desired method( e.g. `-m METHOD_NAME`, default is `TradeBalance`).

  For the complete list of methods supported in this script(same names as in the API), refer to the **Current supported methods** section.

  For the complete list of methods supported by the Kraken API, refer to the [Kraken API documentation](https://www.kraken.com/help/api) .

5. **OPTIONAL argument**. Set the input values for the specified method( e.g. `-i 'pair:XETHZEUR'`). The `-i` expects an input in the form of `'key:value'`.
To get a full description of the method inputs, please refer to the API Docs, where all API methods are described.


## Current supported methods

### Private methods
TradeBalance

### Public methods
Ticker

## TODO
- Support all methods from the API into the script
- Output of the request should be available in different formats(e.g. json, etc)
