# encoding: utf-8
# author: Dominik Richter

require 'messages/version'

module Messages
  def ok(msg, opts = {})
    outputter(opts, "\033[32m[ok]  #{msg}\033[0m")
  end

  def error(msg, opts = {})
    outputter(opts, "\033[31m[xx]  #{msg}\033[0m")
  end

  def warning(msg, opts = {})
    outputter(opts, "\033[33m[!!]  #{msg}\033[0m")
  end

  def stage(msg, opts = {})
    outputter(opts, "\033[36m===== #{msg}\033[0m")
  end

  def info(msg, opts = {})
    outputter(opts, "====> #{msg}")
  end

  def info2(msg, opts = {})
    outputter(opts, "----> #{msg}")
  end

  def info3(msg, opts = {})
    outputter(opts, "    > #{msg}")
  end

  private

  def outputter(opts, msg)
    d = opts[:device] || $stdout
    d.puts(msg)
  end
end
