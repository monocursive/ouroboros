defmodule Ouroboros.Wasm.KeygenTest do
  # Not async: it starts a signing service, which reads the file under test at boot.
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Verifier

  @moduletag :capture_log

  # Written by the real `ouro wasm keygen`, and committed with the exact text it printed.
  # See `test/support/wasm_keygen/README.md` for what this is and is not.
  @fixture Path.expand("../support/wasm_keygen", __DIR__)
  @signer_id "w12-keygen-fixture"

  @bytes "\0asm\x0d\x00\x01\x00 a component this test never runs"

  describe "the file `ouro wasm keygen` writes" do
    # The seam neither language can test alone. The CLI derives a public key with `ring` and
    # prints a `trusted_signers` line; the service derives one with `:crypto` at boot. If
    # those two ever disagree — a different seed format, a different derivation, a base64
    # variant — every artifact that signer issues is refused on every core node, and no
    # round trip inside either language would have noticed.
    test "the signing service reads it and derives the public key the CLI printed" do
      key_path = Path.join(@fixture, "signer.key")

      # Exactly one of the two forms `load_key!/1` documents: base64 of the 32-byte seed,
      # one line. Not raw bytes, and not something the service merely tolerates.
      contents = File.read!(key_path)
      assert String.trim(contents) |> byte_size() == 44
      assert {:ok, seed} = Base.decode64(String.trim(contents))
      assert byte_size(seed) == 32

      service =
        start_supervised!(
          {Service,
           [
             name: nil,
             key_path: key_path,
             signer_id: @signer_id,
             storage:
               {Jido.Storage.ETS,
                table: String.to_atom("keygen_journal_#{System.unique_integer([:positive])}")}
           ]}
        )

      assert {:ok, info} = Service.public_info(service)
      assert info.signer_id == @signer_id
      assert info.trusted_signers_entry == printed_trusted_signers_entry()

      # And the whole point of that line: an artifact this key signs verifies against it.
      {:ok, artifact} =
        Artifact.build(@bytes,
          name: "greeter",
          epoch: 11,
          imports: ["log"],
          author: "keygen-test",
          eval: %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 1_000}
        )

      assert {:ok, signature} =
               Service.sign_artifact(
                 artifact,
                 @signer_id,
                 %{requester: node(), component_bytes: @bytes},
                 service
               )

      {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer_id, value: signature})

      trusted = %{@signer_id => Base.decode64!(printed_public_key())}
      assert :ok = Verifier.verify(signed, @bytes, trusted_signers: trusted)
    end

    test "the printed instructions name the file, the id and the public half" do
      printed = File.read!(Path.join(@fixture, "keygen.out"))

      assert printed =~ "OUROBOROS_SIGNER_ID=#{@signer_id}"
      assert printed =~ "OUROBOROS_UPGRADE_TRUSTED_SIGNERS=#{@signer_id}:"
      assert printed =~ "never leaves the signer"
    end

    # The line an operator pastes into a signer node's environment. `config/runtime.exs`
    # refuses a relative `OUROBOROS_SIGNER_KEY_PATH` — a `:signer` node started with one does
    # not boot — and `ouro wasm keygen --out ./signer.key` used to print exactly that, with
    # the refusal landing on a different machine, later, with nothing in it pointing back.
    # Remove `absolute/1` from the CLI's keygen and this fixture regenerates relative.
    test "the key path it prints is absolute, because a signer node refuses anything else" do
      path =
        @fixture
        |> Path.join("keygen.out")
        |> File.read!()
        |> String.split("\n")
        |> Enum.find_value(fn line ->
          case String.split(String.trim(line), "OUROBOROS_SIGNER_KEY_PATH=", parts: 2) do
            ["", value] -> value
            _other -> nil
          end
        end)

      assert is_binary(path)
      assert Path.type(path) == :absolute, "config/runtime.exs refuses #{inspect(path)}"
      assert Path.basename(path) == "signer.key"
    end
  end

  # The `id:base64` pair out of the committed output, parsed the way an operator's shell
  # would: everything after the first `=`, trimmed.
  defp printed_trusted_signers_entry do
    @fixture
    |> Path.join("keygen.out")
    |> File.read!()
    |> String.split("\n")
    |> Enum.find_value(fn line ->
      case String.split(String.trim(line), "OUROBOROS_UPGRADE_TRUSTED_SIGNERS=", parts: 2) do
        ["", entry] -> entry
        _other -> nil
      end
    end)
  end

  defp printed_public_key do
    [_id, key] = String.split(printed_trusted_signers_entry(), ":", parts: 2)
    key
  end
end
