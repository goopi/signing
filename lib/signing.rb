require "base64"
require "digest/hmac"
require "digest/sha1"

module Signing
  def self.base64_encode(string)
    Base64.urlsafe_encode64(string).gsub(/(=*$)/, "")
  end

  def self.base64_decode(string)
    Base64.urlsafe_decode64(string + "=" * (-string.length % 4))
  end

  # constant-time comparison to prevent timing attacks
  def self.compare(a, b)
    len_eq = a.length == b.length
    res = len_eq ? 0 : 1
    left = len_eq ? a : b
    (0...left.length).each { |i| res |= a[i].ord ^ b[i].ord }
    res == 0
  end

  class Signer
    def initialize(secret, salt)
      @secret = secret
      @salt = salt
      @sep = "."
    end

    def sign(value)
      value = Signing::base64_encode(value)
      value + @sep + get_signature(value)
    end

    def unsign(signed_value)
      return false if not signed_value.include? @sep

      value, s, sig = signed_value.rpartition(@sep)
      if Signing::compare(sig, get_signature(value))
        return Signing::base64_decode(value)
      end

      false
    end

    private

    def get_signature(value)
      key = Digest::SHA1.digest("#{@salt}signer#{@secret}")
      mac = Digest::HMAC.digest(value, key, Digest::SHA1)
      Signing::base64_encode(mac)
    end
  end
end
