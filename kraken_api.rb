#!/usr/bin/env ruby


require 'base64'
require 'securerandom'
require 'addressable/uri'
require 'optparse'
require 'json'
require 'uri'
require 'net/http'


$api_key = nil
$api_secret = nil
$api_version = "0"
$base_uri = "https://api.kraken.com"
$request_type = 'private'
$method_name = 'TradeBalance'
$trading_mode = false
$method_input = Hash.new

class String
  def red;            "\e[31m#{self}\e[0m" end
  def green;          "\e[32m#{self}\e[0m" end
  def blue;           "\e[34m#{self}\e[0m" end
  def bold;           "\e[1m#{self}\e[22m" end
end

def debug(string, stream=STDOUT)
  stream.puts "Debug: ".bold + string.to_s
end

$optparse = OptionParser.new do | opts |
  opts.banner = "This script interacts with the Kraken API, use it as follows:"
  opts.on("-a", "--api-key value", String, "api-key (mandatory)") { |value| $api_key = value }
  opts.on("-p", "--private-key value", String, "api-private-key (mandatory)") { |value| $api_secret = value }
  opts.on("-m", "--method name", String, "more info at https://www.kraken.com/help/api (default: TradeBalance())") { |value| $method_name = value }
  opts.on("-i", "--method-input parameters", String, "eg. asset:ZEUR (optional) ") { |value| $method_input = value }
  opts.on("-t", "--trade mode", TrueClass ,"Trading mode enable during 30m") { |value| $trading_mode = value }
end

$optparse.parse!
def backout(message)
  puts "\n"
  puts $optparse.to_s + "\n" if defined? $optparse
  abort("#{'ERROR:'} #{message}")
end

backout "No api-key specified" if $api_key == nil
backout "No private-key specified" if $api_secret == nil

def get_public(method, input={})
  url = $base_uri + '/' + $api_version + '/public/' + method
  body = encode_options(input)
  uri = URI(url + '?' + body)
  res = Net::HTTP.get_response(uri)
  puts "Response #{res.code} ,  #{res.message}: , #{res.body}"
  return res
end

def post_private(method, input={})
  input['nonce'] = generate_nonce
  post_data = encode_options(input)
  headers = { 'API-Key' => $api_key, 'API-Sign' => generate_message_signature(method, input, post_data) }
  uri = URI.parse($base_uri + url_path(method))
  https = Net::HTTP.new(uri.host,uri.port)
  https.use_ssl = true
  req = Net::HTTP::Post.new(uri.path, headers)
  req.body = post_data
  res = https.request(req)
  puts "Response #{res.code} ,  #{res.message}: , #{res.body}"
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
  key = Base64.decode64($api_secret)
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
    debug("Requested method type => " + "#{method}".bold.green)
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

#check if there is a new order, and retrieve its data
def validate_new_order(methods)
  antwort = methods.send :"TradesHistory" , {}
  check_http_call(antwort,"TradesHistory")
  body = JSON.parse(antwort.body)
  if check_body_content(body,"Balance")
    body["result"]["trades"].keys.each_with_index do |trade, id|
      #We assume index 0 is the last trade
      if id == 0
        puts body["result"]["trades"][trade]
      end
    end
  end
end

def add_order(methods)
  debug "Going to buy something".bold
  # Before placing an order, we need to get the last order ID, to compare against the future order,
  # in order to know when the future order its complete
  validate_new_order(methods)
  # The following is required in order to place the order: 'trading_agreement': 'agree'
  # other_params = { 'trading_agreement': 'agree' }
  # antwort = methods.send :"AddOrder" , {"pair" => "XRPEUR", "type" => "buy", "ordertype" => "market", "volume" => '29', other_params }

end

def trade_invocation()
  methods = Trade_Methods.new
  antwort = methods.send :"Balance" , {}
  check_http_call(antwort,"Balance")
  body = JSON.parse(antwort.body)
  if check_body_content(body,"Balance")
    available_money = body["result"]["ZEUR"].to_f
    if available_money > 50
      puts "#{available_money}"
      add_order(methods)
    else
      debug "Not enough money to trade, current balance: " + "#{available_money} ".red + "EUR".red + ", aborting.."
      exit 1
    end
  end
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

if $trading_mode
  debug "Going to enter trading mode..."
  trade_invocation
else
  methods = Trade_Methods.new
  methods.send :"#{$method_name}" , process_input()
end
