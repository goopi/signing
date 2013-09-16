require File.expand_path("../lib/signing", File.dirname(__FILE__))
include Signing

scope do
  setup do
    {
      :value => "hi",
      :signed_value => "aGk.H9tzyMqq_e4j8yH-0KfNTZvoNBk",
      :secret => "secret",
      :salt => "salt"
    }
  end

  test "should sign the value" do |params|
    s = Signer.new(params[:secret], params[:salt])
    signed_value = s.sign(params[:value])
    assert_equal signed_value, params[:signed_value]

    s = Signer.new("othersecret", params[:salt])
    signed_value = s.sign(params[:value])
    assert signed_value != params[:signed_value]

    s = Signer.new(params[:secret], "othersalt")
    signed_value = s.sign(params[:value])
    assert signed_value != params[:signed_value]
  end

  test "should unsign the signed value" do |params|
    s = Signer.new(params[:secret], params[:salt])
    assert_equal params[:value], s.unsign(params[:signed_value])

    s = Signer.new("othersecret", params[:salt])
    assert_equal false, s.unsign(params[:signed_value])

    s = Signer.new(params[:secret], "othersalt")
    assert_equal false, s.unsign(params[:signed_value])
  end
end
