#!/usr/bin/env ruby
# encoding: utf-8

$:.unshift File.dirname(__FILE__)
require 'sslshake'
require 'json'
require_relative 'messages'
require 'benchmark'
include Messages

ssldummies = '.ssldummies'
testssl = '.testssl'
PORTS = [4443, 4444, 4445, 4446, 4447, 4448, 4449].freeze

def cmd(sth)
  puts '  > '+sth unless ENV['DEBUG'].nil?
  `#{sth}`
end

def print_line(format_str, field, sslrb, testssl)
  a = sslrb.is_a?(Hash) ? sslrb[field.to_sym] : sslrb
  b = testssl.is_a?(Hash) ? testssl[field.to_sym] : testssl
  color = (a == b) ? "\033[32m" : "\033[31m"
  puts format(color + format_str + "\033[0m", field.to_s, a, b)
end

stage 'requirements'
unless File.directory?(ssldummies)
  cmd("git clone git@github.com:arlimus/ssl-test-dummies.git #{ssldummies}")
end
fail unless File.directory?(ssldummies)
ok 'ssl test dummies'

unless File.directory?(testssl)
  cmd("git clone https://github.com/drwetter/testssl.sh #{testssl}")
end
fail unless File.directory?(testssl)
ok 'openssl / testssl'

info 'creating the "ssldummy" docker image'
cmd("cd #{ssldummies} && docker build --tag ssldummy .")
ok 'docker image ready to be used'

info 'start ssl crash test dummies'
cmd("cd #{ssldummies} && ./dummy stop && ./dummy start")
ok 'ssl dummies are ready to be crashed'

puts
stage 'testing'

PORTS.each do |port|
  puts
  info2 "testing port #{port}"

  res0 = {}
  res0time = Benchmark.measure {
    ssl2 = SSLShake.hello('localhost', port: port, protocol: 'ssl2')
    ssl3 = SSLShake.hello('localhost', port: port, protocol: 'ssl3')
    tls10 = SSLShake.hello('localhost', port: port, protocol: 'tls1.0')
    tls11 = SSLShake.hello('localhost', port: port, protocol: 'tls1.1')
    tls12 = SSLShake.hello('localhost', port: port, protocol: 'tls1.2')
    tls13 = SSLShake.hello('localhost', port: port, protocol: 'tls1.3')

    res0 = {
      ssl2:  ssl2['success'] == true,
      ssl3:  ssl3['success'] == true,
      tls10: tls10['success'] == true,
      tls11: tls11['success'] == true,
      tls12: tls12['success'] == true,
      tls13: tls13['success'] == true,
    }
  }

  res1 = {}
  res1time = Benchmark.measure {
    cmd("rm *json; yes | ./#{testssl}/testssl.sh --warnings off --json -p 127.0.0.1:#{port}")
  }
  testssljson = Dir['*.json'][0]
  if testssljson.nil?
    fail 'No openssl output JSON found!!'
  end
  res1_raw = JSON.load(File.read(testssljson))
  res1 = {
    ssl2:  res1_raw.find { |x| x['id'] == 'SSLv2' }['finding'][/not offered/].nil?,
    ssl3:  res1_raw.find { |x| x['id'] == 'SSLv3' }['finding'][/not offered/].nil?,
    tls10: res1_raw.find { |x| x['id'] == 'TLS1' }['finding'][/not offered/].nil?,
    tls11: res1_raw.find { |x| x['id'] == 'TLS1_1' }['finding'][/not offered/].nil?,
    tls12: res1_raw.find { |x| x['id'] == 'TLS1_2' }['finding'][/not offered/].nil?,
    tls13: res1_raw.find { |x| x['id'] == 'TLS1_3' }['finding'][/not offered/].nil?,
  }

  f = '%10s %10s %10s'
  puts format(f, '', 'sslrb', 'openssl')
  %w{ssl2 ssl3 tls10 tls11 tls12 tls13}.each do |prot|
    print_line(f, prot, res0, res1)
  end
  puts format('%10s %9.4fs %9.4fs', 'time', res0time.total, res1time.total)
end

require "pry"; binding.pry if ENV['DEBUG']
