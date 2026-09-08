defmodule Ouroboros.Self.PostureTest do
  @moduledoc """
  What `OUROBOROS_POSTURE=self` requires, and what it refuses (S4, S-D40).

  Async, and it can be: `Ouroboros.Self.Posture.configure/2` reads no application
  environment, no process, and no file except the signer seed a case points it at. That is
  the whole reason it exists as a function rather than as a block in `config/runtime.exs` —
  every refusal below would otherwise need a virtual machine of its own.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Self.Posture

  @model "anthropic:claude-sonnet-5"

  setup do
    {public, _private} = :crypto.generate_key(:eddsa, :ed25519, :crypto.strong_rand_bytes(32))
    %{public: public, signers: "self-dev:" <> Base.encode64(public)}
  end

  describe "no posture at all" do
    test "an unset variable is off, and configures nothing" do
      assert Posture.configure(%{}) == :off
      assert Posture.configure(%{"OUROBOROS_POSTURE" => nil}) == :off
    end

    test "an empty or whitespace value is off rather than a posture named \"\"" do
      assert Posture.configure(%{"OUROBOROS_POSTURE" => ""}) == :off
      assert Posture.configure(%{"OUROBOROS_POSTURE" => "   "}) == :off
    end

    test "any other posture name refuses the boot rather than falling back to off" do
      assert {:error, message} = Posture.configure(%{"OUROBOROS_POSTURE" => "fleet"})
      assert message =~ "OUROBOROS_POSTURE must be \"self\" or unset"
      assert message =~ "\"fleet\""
    end

    test "a near miss is not a posture", %{signers: signers} do
      for typo <- ["Self", "SELF", "self ", " self"] |> Enum.reject(&(String.trim(&1) == "self")) do
        assert {:error, _message} = Posture.configure(env(typo, signers))
      end

      # And the trim is real: a variable an operator exported with a trailing newline is
      # still the posture they meant.
      assert {:ok, _settings} = Posture.configure(env("self ", signers))
    end
  end

  describe "what the posture requires" do
    test "the model, by name", %{signers: signers} do
      env = env("self", signers) |> Map.delete("OUROBOROS_NATIVE_MODEL")

      assert {:error, message} = Posture.configure(env)
      assert message =~ "OUROBOROS_NATIVE_MODEL"
      assert message =~ "there is no session without a model"
    end

    test "a signer: neither a node nor a key is a refusal naming all three", %{signers: signers} do
      env = env("self", signers) |> Map.delete("OUROBOROS_SIGNING_NODE")

      assert {:error, message} = Posture.configure(env)
      assert message =~ "OUROBOROS_SIGNING_NODE"
      assert message =~ "OUROBOROS_SIGNER_KEY_PATH"
      assert message =~ "OUROBOROS_SIGNER_ID"
    end

    test "half a local signer is refused by the half that is missing", context do
      key = key_file(context)

      id_only =
        context
        |> local_env(key)
        |> Map.delete("OUROBOROS_SIGNER_KEY_PATH")

      assert {:error, message} = Posture.configure(id_only)
      assert message =~ "names OUROBOROS_SIGNER_ID and no OUROBOROS_SIGNER_KEY_PATH"

      key_only =
        context
        |> local_env(key)
        |> Map.delete("OUROBOROS_SIGNER_ID")

      assert {:error, message} = Posture.configure(key_only)
      assert message =~ "names OUROBOROS_SIGNER_KEY_PATH and no OUROBOROS_SIGNER_ID"
    end

    test "a relative key path is refused, because `ouro wasm keygen` prints an absolute one",
         context do
      key = key_file(context)
      env = context |> local_env(key) |> Map.put("OUROBOROS_SIGNER_KEY_PATH", "signer.key")

      assert {:error, message} = Posture.configure(env)
      assert message =~ "must be an absolute path"
    end

    test "a key path naming nothing is refused before the supervision tree tries it",
         context do
      key = key_file(context)
      env = context |> local_env(key) |> Map.put("OUROBOROS_SIGNER_KEY_PATH", key <> ".gone")

      assert {:error, message} = Posture.configure(env)
      assert message =~ "is not a readable file"
    end

    test "trusted signers, and an empty list is not a list", %{signers: signers} do
      assert {:error, missing} =
               Posture.configure(
                 env("self", signers)
                 |> Map.delete("OUROBOROS_UPGRADE_TRUSTED_SIGNERS")
               )

      assert missing =~ "requires OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
      assert missing =~ "a node that trusts nobody can deploy nothing"

      assert {:error, empty} = Posture.configure(env("self", ","))
      assert empty =~ "lists nobody"
    end

    test "a malformed trusted-signers entry is a refusal, not a narrowed set" do
      assert {:error, no_colon} = Posture.configure(env("self", "just-an-id"))
      assert no_colon =~ "signer_id:base64_ed25519_public_key"

      assert {:error, short} = Posture.configure(env("self", "dev:" <> Base.encode64("short")))
      assert short =~ "32-byte Ed25519 public key"

      assert {:error, not_base64} = Posture.configure(env("self", "dev:not base64 at all"))
      assert not_base64 =~ "32-byte Ed25519 public key"
    end

    test "a signer listed twice is refused rather than deduplicated", %{signers: signers} do
      assert {:error, message} = Posture.configure(env("self", signers <> "," <> signers))
      assert message =~ "more than once"
    end
  end

  describe "what the posture will not run under" do
    test "a build whose forge placement was moved off :local", %{signers: signers} do
      assert {:error, message} =
               Posture.configure(env("self", signers), wasm_forge_placement: :builder)

      assert message =~ ":wasm_forge_placement"
      assert message =~ ":builder"
    end

    test "a build whose lane-W eval requirement was turned off", %{signers: signers} do
      assert {:error, message} =
               Posture.configure(env("self", signers), signing_require_wasm_eval: false)

      assert message =~ ":signing_require_wasm_eval"
    end

    test "the defaults are what it expects, so an empty settings list passes", %{signers: signers} do
      assert {:ok, _settings} = Posture.configure(env("self", signers), [])
    end
  end

  describe "what the posture configures" do
    test "the fleet arm: a signing node, and no key on this machine", context do
      assert {:ok, settings} = Posture.configure(env("self", context.signers))

      assert settings[:native_forge_tool] == true
      assert settings[:permissions_engine] == Ouroboros.Wasm.PolicyEngine
      assert settings[:self_posture] == true
      assert settings[:self_ship] == true
      assert settings[:signing_node] == :signer@fleet

      # The application starts no local signing service without one of these.
      refute Keyword.has_key?(settings, :signer_key_path)
    end

    test "the one-machine arm: a key beside the application", context do
      key = key_file(context)

      assert {:ok, settings} = Posture.configure(local_env(context, key))

      assert settings[:signer_key_path] == key
      assert settings[:signer_id] == "self-dev"
      refute Keyword.has_key?(settings, :signing_node)
    end

    test "trust is closed and named, whatever config/config.exs says outside production",
         context do
      assert {:ok, settings} = Posture.configure(env("self", context.signers))

      assert settings[:upgrade_trust_policy][:allow_unsigned] == false
      assert settings[:upgrade_trust_policy][:trusted_signers] == %{"self-dev" => context.public}
    end

    test "two signers, because the exporting installation's key is a second one", context do
      {other, _private} = :crypto.generate_key(:eddsa, :ed25519, :crypto.strong_rand_bytes(32))
      listed = context.signers <> ", shipped-from-elsewhere:" <> Base.encode64(other)

      assert {:ok, settings} = Posture.configure(env("self", listed))

      assert settings[:upgrade_trust_policy][:trusted_signers] == %{
               "self-dev" => context.public,
               "shipped-from-elsewhere" => other
             }
    end

    test "OUROBOROS_SELF_SHIP=false takes the posture without taking priv/self", context do
      for value <- ["false", "0"] do
        env = env("self", context.signers) |> Map.put("OUROBOROS_SELF_SHIP", value)
        assert {:ok, settings} = Posture.configure(env)
        assert settings[:self_ship] == false
        assert settings[:self_posture] == true
      end

      for value <- ["true", "1"] do
        env = env("self", context.signers) |> Map.put("OUROBOROS_SELF_SHIP", value)
        assert {:ok, settings} = Posture.configure(env)
        assert settings[:self_ship] == true
      end
    end

    test "an unusable OUROBOROS_SELF_SHIP is a refusal rather than either default", context do
      env = env("self", context.signers) |> Map.put("OUROBOROS_SELF_SHIP", "yes")

      assert {:error, message} = Posture.configure(env)
      assert message =~ "OUROBOROS_SELF_SHIP must be true or false"
    end

    test "it never widens what a component may resolve", context do
      assert {:ok, settings} = Posture.configure(env("self", context.signers))

      # `:policy_allowable_tools` is an operator typing a tool name and
      # `Ouroboros.Control.PolicyPromotion` is the earned half. Neither is reachable from an
      # environment variable, and this is the assertion that keeps it that way.
      refute Keyword.has_key?(settings, :policy_allowable_tools)
      refute Keyword.has_key?(settings, :wasm_policy)
    end
  end

  describe "the trusted-signers parser, which the export writes for" do
    test "round-trips the exact line `ouro wasm keygen` prints", %{public: public} do
      line = "prod-key:" <> Base.encode64(public)
      assert Posture.trusted_signers(line) == {:ok, %{"prod-key" => public}}
    end

    test "an absent variable trusts nobody rather than raising" do
      assert Posture.trusted_signers(nil) == {:ok, %{}}
    end

    test "whitespace around entries is an operator's line wrap, not a signer id", %{
      public: public
    } do
      line = " a:#{Base.encode64(public)} , b:#{Base.encode64(public)} "
      assert {:ok, signers} = Posture.trusted_signers(line)
      assert Map.keys(signers) |> Enum.sort() == ["a", "b"]
    end

    test "an empty id or an empty key is malformed" do
      assert {:error, _} = Posture.trusted_signers(":" <> Base.encode64(<<0::256>>))
      assert {:error, _} = Posture.trusted_signers("dev:")
    end
  end

  test "variables/0 names every variable the posture reads" do
    assert Posture.variables() == [
             "OUROBOROS_POSTURE",
             "OUROBOROS_NATIVE_MODEL",
             "OUROBOROS_SIGNING_NODE",
             "OUROBOROS_SIGNER_KEY_PATH",
             "OUROBOROS_SIGNER_ID",
             "OUROBOROS_UPGRADE_TRUSTED_SIGNERS",
             "OUROBOROS_SELF_SHIP"
           ]

    assert Posture.posture_env() == "OUROBOROS_POSTURE"
  end

  ## helpers

  defp env(posture, signers) do
    %{
      "OUROBOROS_POSTURE" => posture,
      "OUROBOROS_NATIVE_MODEL" => @model,
      "OUROBOROS_SIGNING_NODE" => "signer@fleet",
      "OUROBOROS_UPGRADE_TRUSTED_SIGNERS" => signers
    }
  end

  defp local_env(context, key) do
    context.signers
    |> then(&env("self", &1))
    |> Map.delete("OUROBOROS_SIGNING_NODE")
    |> Map.put("OUROBOROS_SIGNER_KEY_PATH", key)
    |> Map.put("OUROBOROS_SIGNER_ID", "self-dev")
  end

  defp key_file(_context) do
    dir = Path.join(System.tmp_dir!(), "ouro-posture-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    path = Path.join(dir, "signer.key")
    File.write!(path, Base.encode64(:crypto.strong_rand_bytes(32)))
    File.chmod!(path, 0o600)
    path
  end
end
