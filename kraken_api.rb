#!/usr/bin/env ruby


require 'base64'
require 'securerandom'
require 'addressable/uri'
require 'optparse'
require 'json'
require 'uri'
require 'net/http'


$api_version = "0"
$base_uri = "https://api.kraken.com"
$method_input = Hash.new
$options = {}


class String
  def red;            "\e[31m#{self}\e[0m" end
  def green;          "\e[32m#{self}\e[0m" end
  def blue;           "\e[34m#{self}\e[0m" end
  def bold;           "\e[1m#{self}\e[22m" end
end

def debug(string, stream=STDOUT)
  stream.puts "Debug: ".bold + string.to_s
end

subtext = <<HELP
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
HELP


global = OptionParser.new do |opts|
  opts.banner = "kraken_api interacts with the Kraken API\nFind more information at https://www.kraken.com/help/api"
  opts.separator ""
  opts.separator subtext
end


subcommands = {
  'TradeBalance' => OptionParser.new do |opts|
     opts.banner = "Usage: TradeBalance [api-key] [private-key] [input]"
     opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
     opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
     opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
  end,
   'Balance' => OptionParser.new do |opts|
      opts.banner = "Usage: Balance [api-key] [private-key] [input]"
      opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
      opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
      opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
   end,
   'Ticker' => OptionParser.new do |opts|
      opts.banner = "Usage: Ticker [api-key] [private-key] [input]"
      opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
      opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
      opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
   end,
   'Assets' => OptionParser.new do |opts|
      opts.banner = "Usage: Assets [api-key] [private-key] [input]"
      opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
      opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
      opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
   end,
   'AssetPairs' => OptionParser.new do |opts|
      opts.banner = "Usage: AssetPairs [api-key] [private-key] [input]"
      opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
      opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
      opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
   end,
   'Trades' => OptionParser.new do |opts|
      opts.banner = "Usage: Trades [api-key] [private-key] [input]"
      opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
      opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
      opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
   end,
   'OHLC' => OptionParser.new do |opts|
      opts.banner = "Usage: OHLC [api-key] [private-key] [input]"
      opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
      opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
      opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
   end,
   'TradingMode' => OptionParser.new do |opts|
      opts.banner = "Usage: TradingMode -a SOMETHING -p SOMETHING -c XRPEUR -t XXRPZEUR -v 600 -l 1 -w 4"
      opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $options[:api_key] = value }
      opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $options[:api_secret] = value }
      opts.on("-c", "--coin type", String, "coin to buy, e.g. XRPEUR, ETHEUR") { |value| $options[:coin] = value }
      opts.on("-t", "--ticker type", String, "ticker to trade, e.g. XXRPZEUR, XETHZEUR") { |value| $options[:ticker] = value }
      opts.on("-v", "--volume amount", String, "volume to trade, e.g. 600") { |value| $options[:volume] = value }
      opts.on("-l", "--lose-minimum percentage", Float, "min percentage that can be lost, before selling, e.g. 1") { |value| $options[:minimum] = value }
      opts.on("-w", "--win-maximum percentage", Float, "percentage expected to win, before selling, e.g. 4") { |value| $options[:maximum] = value }
   end
}

global.order!
command = ARGV.shift
$options[:method] = command
subcommands[command].order! unless subcommands[command].nil?

def backout(message)
  puts "\n"
  abort("#{'ERROR:'} #{message}")
end

backout "No command specified, use --help for more information" if $options[:method] == nil
backout "No api-key specified" if $options[:api_key] == nil
backout "No private-key specified" if $options[:api_secret] == nil

def get_public(method, input={})
  url = $base_uri + '/' + $api_version + '/public/' + method
  body = encode_options(input)
  uri = URI(url + '?' + body)
  res = Net::HTTP.get_response(uri)
  puts "Response #{res.code} ,  #{res.message}: , #{res.body}"  if !$options[:method].eql?("TradingMode")
  return res
end

def post_private(method, input={})
  input['nonce'] = generate_nonce
  post_data = encode_options(input)
  headers = { 'API-Key' => $options[:api_key], 'API-Sign' => generate_message_signature(method, input, post_data) }
  uri = URI.parse($base_uri + url_path(method))
  https = Net::HTTP.new(uri.host,uri.port)
  https.use_ssl = true
  req = Net::HTTP::Post.new(uri.path, headers)
  req.body = post_data
  res = https.request(req)
  puts "Response #{res.code} ,  #{res.message}: , #{res.body}" if !$options[:method].eql?("TradingMode")
  return res
end

# Sets the query component for this URI from a Hash object(POST data)
def encode_options(input)
  uri = Addressable::URI.new
  uri.query_values = input
  uri.query
end

# API-Sign = Message signature using HMAC-SHA512 of (URI path + SHA256(nonce + POST data)) and base64 decoded secret API key
def generate_message_signature(method, input={}, post_data)
  key = Base64.decode64($options[:api_secret])
  message = generate_message(method, post_data, input)
  generate_api_signature(key, message)
end

# Message formula is URI path + SHA256(nonce + POST data)
def generate_message(method, post_data, input)
  digest = OpenSSL::Digest.new('sha256', input['nonce'] + post_data).digest
  url_path(method) + digest
end

def url_path(method)
  '/' + $api_version + '/private/' + method
end

def generate_api_signature(key, message)
  Base64.strict_encode64(OpenSSL::HMAC.digest('sha512', key, message))
end


def generate_nonce
  #for the higher 48 bits, use the current timestamp to generate it
  high_bits = (Time.now.to_f * 10000).to_i << 16
  #for the 16 low bits, use the Bitwise AND operator to generate it
  low_bits  = SecureRandom.random_number(2 ** 16) & 0xffff
  #for the 64 bits, use the Bitwise OR operator, based on the value of the 16 and 48 bits numbers
  (high_bits | low_bits).to_s
end


class Trade_Methods
  def output_debug(type, method, input={})
    type.eql?("private") ? debug("Going to request => " + "private user data".bold.green) : debug("Going to request => " + "public market data.".bold.green )
    debug("Requested method type => " + $options[:method].bold.green)
    input.empty? ? debug("No inputs available for this method, using default values".red) : debug("Input: => " + "#{input}".blue)
  end
  ###################### private methods ######################

  #TODO: add an argument description per method

  def Balance(input={})
    output_debug("private", 'Balance', input)
    post_private 'Balance', input
  end

  #method names lose consistency, but I prefer them to be exactly as the names in the API docs, read https://www.kraken.com/help/api
  def TradeBalance(input={})
    output_debug("private", 'TradeBalance', input)
    post_private 'TradeBalance', input
  end

  def OpenOrders(input={})
    output_debug("private", 'OpenOrders', input)
    post_private 'OpenOrders', input
  end


  def ClosedOrders(input={})
    output_debug("private", 'ClosedOrders', input)
    post_private 'ClosedOrders', input
  end

  # TODO: define mandatory arguments
  # def QueryOrders(input={})
  #   output_debug("private", 'QueryOrders', input)
  #   post_private 'QueryOrders', input
  # end

  def TradesHistory(input={})
    output_debug("private", 'TradesHistory', input)
    post_private 'TradesHistory', input
  end

  # TODO: define mandatory arguments
  # def QueryTrades(input={})
  #   output_debug("private", 'QueryTrades', input)
  #   post_private 'QueryTrades', input
  # end

  def TradeVolume(input={})
    output_debug("private", 'TradeVolume', input)
    post_private 'TradeVolume', input
  end

  ###################### private methods trading ######################

  def AddOrder(input={})
    output_debug("private", 'AddOrder', input)
    post_private 'AddOrder', input
  end


  ###################### public methods ######################

  #method names lose consistency, but I prefer them to be exactly as the names in the API docs, read https://www.kraken.com/help/api

  #-m Ticker -i "pair:XRPEUR"
  def Ticker(input={}) #SELECTED
    output_debug("public", 'Ticker', input)
    get_public 'Ticker', input
  end

  def Time(input={})
    output_debug("public", 'Time', input)
    get_public 'Time', input
  end

  def Assets(input={})
    output_debug("public", 'Assets', input)
    get_public 'Assets', input
  end

  #-m AssetPairs -i "pair:XRPEUR"
  def AssetPairs(input={})
    output_debug("public", 'AssetPairs', input)
    get_public 'AssetPairs', input
  end

  #-m OHLC -i "pair:XRPEUR&interval:15&since:1516482900"
  def OHLC(input={}) # Can help to verify trend in the series data, interested in the CLOSE value
    output_debug("public", 'OHLC', input)
    get_public 'OHLC', input
  end

  def Trades(input={})
    output_debug("public", 'Trades', input)
    get_public 'Trades', input
  end

  def Spread(input={})
    output_debug("public", 'Trades', input)
    get_public 'Spread', input
  end
end

def check_http_call(http_output, method)
  if http_output.code.eql?('200')
    debug("Retrieving " + "#{method}".bold.green + " request, successfully")
  else
    debug("Retrieving " + "#{method}".bold.green + " request, failed, going to exit...")
    exit 1
  end
end

def check_body_content(body, method)
  if body["error"].empty?
    return true
  end
  debug "http" + "#{method}".bold.green + "call return an invalid result, going to exit.."
  exit 1
end

def is_new_order_placed?(methods, last_trade)
  new_trade_id, new_trade_info = validate_new_order(methods)
  if !new_trade_id.eql?(last_trade)
    return true, new_trade_info
  end
  return false, nil
end

#check if there is a new order, and retrieve its data
def validate_new_order(methods)
  antwort = methods.send :"TradesHistory" , {}
  check_http_call(antwort,"TradesHistory")
  body = JSON.parse(antwort.body)
  if check_body_content(body,"Balance")
    body["result"]["trades"].keys.each_with_index do |trade, id|
      if id == 0
        return trade, body["result"]["trades"][trade]
      end
    end
  end
end

#loop here until its time to sell
def sell_or_buy(methods, info)
  trade_status = false
  trade_coin_price = info["price"].to_f
  trade_coin_vol = info["vol"]
  #Invoke Ticker and get coin current BID price
  pair_value = "#{$options[:coin]}"
  antwort = methods.send :"Ticker" , {"pair"=>"#{pair_value}"}
  check_http_call(antwort,"Ticker")
  body = JSON.parse(antwort.body)
  if check_body_content(body,"Balance")
    current_coin_price = body["result"]["#{$options[:ticker]}"]["b"][0].to_f
    # current_coin_price = body["result"]["XETHZEUR"]["b"][0].to_f
    delta = current_coin_price > trade_coin_price ? (current_coin_price - trade_coin_price) : (trade_coin_price - current_coin_price)
    percentage = (delta * 100) / (trade_coin_price)
    current_coin_price > trade_coin_price ? (puts "Price of buy: #{trade_coin_price}, current price: #{current_coin_price}, positive percentage is: #{percentage}") : (puts "Price of buy: #{trade_coin_price}, current price: #{current_coin_price}, negative percentage is: #{percentage}")
    trade_status = current_coin_price > trade_coin_price ? true : false
    if !trade_status
      if percentage > $options[:minimum]
        puts "going to sell, loosing"
        other_params = { 'trading_agreement' => 'agree' }
        antwort = methods.send :"AddOrder" , {"pair" => "#{$options[:coin]}", "type" => "sell", "ordertype" => "market", "volume" => "#{$options[:volume]}", 'trading_agreement' => 'agree' }
        return true
      else
        puts "Waiting for next iteration.."
        sleep(60)
        return false
      end
    else
      if percentage > $options[:maximum]
        puts "going to sell, winning"
        other_params = { 'trading_agreement' => 'agree' }
        antwort = methods.send :"AddOrder" , {"pair" => "#{$options[:coin]}", "type" => "sell", "ordertype" => "market", "volume" => "#{$options[:volume]}", 'trading_agreement' => 'agree' }
        return true
      else
        puts "Waiting for next iteration.."
        sleep(60)
        return false
      end
    end
  end
end

def add_order(methods)
  debug "Going to buy something".bold
  last_trade, last_trade_info = validate_new_order(methods)
  ################### PLACE ORDER ###################
  # The following is required in order to place the order: 'trading_agreement': 'agree'
  antwort = methods.send :"AddOrder" , {"pair" => "#{$options[:coin]}", "type" => "buy", "ordertype" => "market", "volume" => "#{$options[:volume]}", 'trading_agreement' => 'agree' }
  puts antwort
  ################### END ###########################
  new_trade_id, new_trade_info = validate_new_order(methods)
  flaggy = false
  until flaggy
    flaggy = sell_or_buy(methods, new_trade_info)
  end
end

def trade_invocation()
  methods = Trade_Methods.new
  antwort = methods.send :"Balance" , {}
  check_http_call(antwort,"Balance")
  body = JSON.parse(antwort.body)
  add_order(methods) if check_body_content(body,"Balance")
end

def process_input()
  input_hash = Hash.new
  return {} if $method_input.empty?
  if $method_input.include?('&')
    $method_input.strip.split('&').each do |argument|
      if argument.include?(':')
        hash_values = argument.split(':')
        input_hash[hash_values[0]] = hash_values[1]
      else
        debug("Input is not valid".red.bold )
        exit(1)
      end
    end
  elsif $method_input.include?(':') & !$method_input.include?('&')
    hash_values = $method_input.split(':')
    input_hash = {
      "#{hash_values[0]}" => "#{hash_values[1]}"}
  else
    debug("Input is not valid".red.bold )
    exit(1)
  end
  return input_hash
end

if $options[:method].eql?("TradingMode")
  debug "Going to enter trading mode..."
  trade_invocation
else
  methods = Trade_Methods.new
  methods.send :"#{$options[:method]}" , process_input()
end
