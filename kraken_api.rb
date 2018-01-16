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
  if res.code.eql?'200'
    exit 0
  else
    exit 1
  end
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
  if res.code.eql?'200'
    exit 0
  else
    exit 1
  end
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
  def Ticker(input={})
    output_debug("public", 'Ticker', input)
    get_public 'Ticker', input
  end
end


#TODO: fix ugly method code
def process_input()
  input_hash = Hash.new
  return {} if $method_input.empty?
  if $method_input.include?(',')
    $method_input.split(',').each do |element|
        hash_values = element.split(':')
        input_hash[hash_values[0]] = hash_values[1]
    end
  else
    hash_values = $method_input.split(':')
    input_hash = {
      "#{hash_values[0]}" => "#{hash_values[1]}"
    }
  end
  return input_hash
end

methods = Trade_Methods.new
methods.send :"#{$method_name}" , process_input()
