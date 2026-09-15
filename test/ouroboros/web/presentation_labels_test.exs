defmodule Ouroboros.Web.PresentationTest do
  @moduledoc """
  The two functions that stand between the runtime's vocabulary and a template.

  Named `presentation_labels_test.exs` because `presentation_test.exs` in this directory
  already belongs to `Ouroboros.EventPresentation`, which is the transcript projection and
  a different thing entirely.

  Every case here is a string the review found on screen
  (`docs/design-qa/ui-review-2026-09-15.md` §3.5) or the shape that produced it.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Web.Presentation

  describe "node_label/1" do
    test "a runtime nobody named is this computer" do
      # The four spellings of the same fact: nothing said, or the BEAM's word for nothing
      # having been said.
      for absent <- [nil, "", "   ", :nonode@nohost, "nonode@nohost"] do
        assert Presentation.node_label(absent) == "this computer",
               "#{inspect(absent)} did not read as an unnamed runtime"
      end
    end

    test "a named node reads as its host, which is the half that names the machine" do
      assert Presentation.node_label(:"ouro@build-box") == "build-box"
      assert Presentation.node_label("alpha@10.0.0.4") == "10.0.0.4"
    end

    test "two machines in one fleet are two words, not one" do
      # The half before the `@` is the release name and every machine in a fleet shares it.
      # Shortening to it put "ouro" under both presence dots, so a reader could not tell
      # which machine had gone dark.
      assert Presentation.node_label(:ouro@alpha) == "alpha"
      assert Presentation.node_label(:ouro@beta) == "beta"

      refute Presentation.node_label(:ouro@alpha) == Presentation.node_label(:ouro@beta)
    end

    test "a node name with no host is itself" do
      assert Presentation.node_label("alpha") == "alpha"
    end

    test "a host with no release in front of it is the host" do
      assert Presentation.node_label("@build-box") == "build-box"
    end

    test "a fleet that knows what a machine is called outranks the string split" do
      machines = [%{node: :"ouro@build-box", machine: "the build box"}]

      assert Presentation.node_label(:"ouro@build-box", machines) == "the build box"

      # And a roster entry for some other node changes nothing about this one.
      assert Presentation.node_label(:ouro@laptop, machines) == "laptop"
    end

    test "a roster label that only repeats the node teaches nothing and is ignored" do
      machines = [%{node: "ouro@build-box", machine: "ouro@build-box"}]
      assert Presentation.node_label("ouro@build-box", machines) == "build-box"
    end

    test "something that is not a node name says so rather than claiming to be local" do
      # Absent is "this computer"; unreadable is a different fact, and spelling them the
      # same would be the surface claiming something nothing reported.
      assert Presentation.node_label(%{unexpected: true}) == "not reported"
    end
  end

  describe "refusal/1" do
    test "the audit refusal the page opened with is a sentence" do
      # Live, §3.5: `/audit` drew `Audit operation failed: :audit_disabled` as its first
      # line whenever recording was off. `gateway/methods.ex:611` is where the atom gets
      # inspected into the message, so the message is what has to be read back.
      sentence = Presentation.refusal("Audit operation failed: :audit_disabled")

      assert sentence =~ "Audit recording is disabled on this runtime"
      refute sentence =~ ":audit_disabled"
    end

    test "the same condition arrives in four shapes and answers the same sentence" do
      sentence = Presentation.refusal(:audit_disabled)
      assert sentence == "Audit recording is disabled on this runtime."

      assert Presentation.refusal({:error, :audit_disabled}) == sentence

      # Through a message the gateway wrote, the half it wrote is kept in front of it:
      # "Audit operation failed" is what the runtime said, and it is not this module's to
      # throw away.
      framed = "Audit operation failed: " <> sentence

      for shape <- [
            {:error, -32_004, "Audit operation failed: :audit_disabled"},
            {:error, -32_004, "Audit operation failed: :audit_disabled", %{}},
            %{code: -32_004, message: "Audit operation failed: :audit_disabled"}
          ] do
        assert Presentation.refusal(shape) == framed, "#{inspect(shape)} read differently"
      end
    end

    # ---------------------------------------------------------------- adopted review proofs

    test "a code-shaped run of digits inside a message is content, not punctuation" do
      # PROOF G, inverted. `without_codes/1` used to delete any `-32ddd` anywhere, which
      # rewrote a path the runtime had named.
      assert Presentation.refusal({:error, -32_602, "cannot read /var/log/ouro-32001/boot"}) ==
               "cannot read /var/log/ouro-32001/boot"

      assert Presentation.refusal("over budget by -32500 tokens") ==
               "over budget by -32500 tokens"
    end

    test "the half of a message in front of a known term is kept" do
      # PROOF G, inverted: the verb that was refused is the operator's whole question, and
      # the sentence used to replace it rather than follow it.
      sentence =
        Presentation.refusal(
          {:error, -32_003, "read scope may not run interactive.answer: :unavailable"}
        )

      assert sentence =~ "read scope may not run interactive.answer"
      assert sentence =~ "not available here"
    end

    test "a condition the message already spells is not said twice" do
      assert Presentation.refusal("Audit operation failed: :audit_operation_failed") ==
               "Audit operation failed."
    end

    test "an inspected term reaches the page as words, not as Elixir" do
      # PROOF G, inverted. Nothing is evaluated: the punctuation `inspect/1` added is taken
      # back off, and no cause is invented for what is left.
      enoent = Presentation.refusal(~s(Audit operation failed: {:enoent, "/var/lib/ouro"}))

      assert enoent == "Audit operation failed: enoent, /var/lib/ouro."
      refute enoent =~ "{"
      refute enoent =~ ~s(")

      assert Presentation.refusal({:error, {:shutdown, :closed}}) ==
               "The runtime reported: shutdown, closed."

      # A 3-tuple whose second element is not a code is not the gateway's shape; the
      # message half is still the only thing in it a person can read.
      assert Presentation.refusal({:error, nil, "boom"}) == "boom"
    end

    test "the outcome-unknown marker survives the translation" do
      # PROOF G, inverted. `Ouroboros.Web.Call`'s moduledoc calls the difference between
      # "did not happen" and "happened and was not reported" the operator's whole question.
      unknown = Presentation.refusal({:error, -32_005, "", %{"outcome" => "unknown"}})
      plain = Presentation.refusal({:error, -32_005, ""})

      refute unknown == plain
      assert unknown =~ plain
      assert unknown =~ "Whether it happened anyway is not something this runtime reported."
    end

    test "a success is not dressed as a refusal" do
      # PROOF G, inverted: `:ok` used to read "Ok.".
      assert Presentation.refusal(:ok) == nil
    end

    test "a code that arrived as a string is still a code" do
      assert Presentation.refusal(%{"code" => "-32004", "message" => nil}) ==
               Presentation.refusal({:error, -32_004, ""})
    end

    test "every code this runtime can answer with has a sentence of its own" do
      # The table is the enforcement point: emptied, every refusal collapses to one
      # sentence that says nothing about which refusal it was.
      for {code, expected} <- [
            {-32_001, "authenticated"},
            {-32_003, "scope"},
            {-32_004, "not available"},
            {-32_005, "stopped answering"},
            {-32_007, "no record"},
            {-32_601, "does not serve"},
            {-32_602, "parameters"}
          ] do
        sentence = Presentation.refusal({:error, code, ""})

        assert sentence =~ expected,
               "#{code} does not read as #{inspect(expected)}: #{inspect(sentence)}"

        refute sentence == "The runtime refused this and did not say why.",
               "#{code} fell through to the generic sentence"
      end
    end

    test "a numeric code never reaches the sentence" do
      for code <- [-32_001, -32_003, -32_004, -32_007] do
        sentence = Presentation.refusal({:error, code, ""})

        assert is_binary(sentence) and sentence != ""
        refute sentence =~ to_string(code)
        refute sentence =~ "-32"
      end
    end

    test "a bracketed or trailing code is punctuation and is taken out" do
      assert Presentation.refusal("the fleet helper is unavailable (-32004)") ==
               "the fleet helper is unavailable"

      assert Presentation.refusal("the fleet helper is unavailable: -32004") ==
               "the fleet helper is unavailable"
    end

    test "a term with no sentence of its own is still words, never an atom" do
      sentence = Presentation.refusal(:some_condition_nobody_wrote_a_sentence_for)

      refute sentence =~ ":some_condition"
      assert sentence == "Some condition nobody wrote a sentence for."
    end

    test "a message the runtime wrote for a person is kept" do
      assert Presentation.refusal({:error, -32_602, "workspace must be an absolute path"}) ==
               "workspace must be an absolute path"
    end

    test "nothing in, nothing out, so a template can draw a refusal only when there is one" do
      assert Presentation.refusal(nil) == nil
    end
  end
end
