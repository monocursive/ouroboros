defmodule Ouroboros.Gateway.ConfigTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Gateway.Config

  @token String.duplicate("t", 32)

  defp valid(overrides \\ []) do
    Keyword.merge([token: @token, data_dir: "/tmp/ouroboros-gateway-test"], overrides)
  end

  describe "what it refuses" do
    test "a gateway with no token source is not a gateway" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_TOKEN_FILE/, fn ->
        Config.new!(data_dir: "/tmp/ouroboros-gateway-test")
      end

      # The fallback variable is named too: an operator who reached for the env var is
      # the one most likely to have left it unset.
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_TOKEN\b/, fn ->
        Config.new!(data_dir: "/tmp/ouroboros-gateway-test")
      end
    end

    test "a token too short to be worth checking is refused, with its length named" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_TOKEN/, fn ->
        Config.new!(valid(token: "hunter2"))
      end

      assert_raise ArgumentError, ~r/7 bytes/, fn -> Config.new!(valid(token: "hunter2")) end
    end

    test "leaving loopback requires the override to have been typed out" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_ALLOW_REMOTE/, fn ->
        Config.new!(valid(bind: "0.0.0.0"))
      end

      # The refusal explains the actual risk rather than only naming the flag.
      assert_raise ArgumentError, ~r/cleartext/, fn -> Config.new!(valid(bind: "10.0.0.4")) end
    end

    test "an enabled gateway with nowhere to publish its port is refused" do
      assert_raise ArgumentError, ~r/OUROBOROS_DATA_DIR/, fn -> Config.new!(token: @token) end

      assert_raise ArgumentError, ~r/OUROBOROS_DATA_DIR/, fn ->
        Config.new!(token: @token, data_dir: "   ")
      end
    end

    test "every other malformed value names its own variable" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_PORT/, fn ->
        Config.new!(valid(port: 70_000))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_BIND/, fn ->
        Config.new!(valid(bind: "not-an-address"))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_SCOPE/, fn ->
        Config.new!(valid(scope: :admin))
      end

      # A max frame below the size of a `hello` would fail every connection with an
      # error naming the wrong cause.
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_MAX_FRAME/, fn ->
        Config.new!(valid(max_frame: 16))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_QUEUE_LIMIT/, fn ->
        Config.new!(valid(queue_limit: 0))
      end
    end

    test "an unreadable token file is refused by path" do
      path = Path.join(System.tmp_dir!(), "ouroboros-gateway-absent-#{System.unique_integer()}")

      error =
        assert_raise ArgumentError, fn ->
          Config.new!(token_file: path, data_dir: "/tmp/ouroboros-gateway-test")
        end

      assert error.message =~ "OUROBOROS_GATEWAY_TOKEN_FILE=#{path}"
      assert error.message =~ "no such file or directory"
    end
  end

  describe "what it accepts" do
    test "loopback defaults, with the ephemeral port that removes the bind race" do
      config = Config.new!(valid())

      assert config.bind == {127, 0, 0, 1}
      assert config.port == 0
      assert config.scope == :read
      assert config.allow_shutdown == false
      assert config.max_frame == 1_048_576
      assert config.queue_limit == 1_000
    end

    test "a token file wins over the environment token and is trimmed" do
      path = Path.join(System.tmp_dir!(), "ouroboros-gateway-token-#{System.unique_integer()}")
      File.write!(path, "  " <> String.duplicate("f", 40) <> "\n")
      on_exit(fn -> File.rm(path) end)

      config = Config.new!(token_file: path, token: @token, data_dir: "/tmp/x")

      assert config.token == String.duplicate("f", 40)

      # The path is kept because `gateway.json` publishes it: a client that did not spawn
      # this daemon has to be told where the credential is, and a path is not one.
      assert config.token_file == path
    end

    test "an environment token publishes no path, because there is no file to name" do
      config = Config.new!(valid())

      assert config.token == @token
      assert is_nil(config.token_file)
    end

    test "a non-loopback bind is accepted once the override says so" do
      config = Config.new!(valid(bind: "0.0.0.0", allow_remote: true))

      assert config.bind == {0, 0, 0, 0}
      assert config.allow_remote == true
      refute Config.loopback?(config.bind)
    end

    test "IPv6 loopback is loopback" do
      config = Config.new!(valid(bind: "::1"))

      assert config.bind == {0, 0, 0, 0, 0, 0, 0, 1}
      assert Config.loopback?(config.bind)
      assert Config.bind_to_string(config.bind) == "::1"
    end

    test "an unknown key is ignored so an older node survives a newer runtime.exs" do
      assert %Config{} = Config.new!(valid(subscriptions_enabled: true))
    end
  end

  describe "inspection" do
    test "the token never renders, and everything else still does" do
      rendered = inspect(Config.new!(valid(port: 4560)))

      refute rendered =~ @token
      assert rendered =~ "redacted"
      assert rendered =~ "4560"
    end
  end

  test "a node that was never told to serve a gateway does not serve one" do
    refute Config.enabled?()
  end
end
