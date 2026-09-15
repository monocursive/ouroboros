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

    test "a named node reads as the machine, not as the BEAM's address for it" do
      assert Presentation.node_label(:"ouro@build-box") == "ouro"
      assert Presentation.node_label("alpha@10.0.0.4") == "alpha"
    end

    test "a node name with no host is itself" do
      assert Presentation.node_label("alpha") == "alpha"
    end

    test "a fleet that knows what a machine is called outranks the string split" do
      machines = [%{node: :"ouro@build-box", machine: "build-box"}]

      assert Presentation.node_label(:"ouro@build-box", machines) == "build-box"

      # And a roster entry for some other node changes nothing about this one.
      assert Presentation.node_label(:ouro@laptop, machines) == "ouro"
    end

    test "a roster label that only repeats the node teaches nothing and is ignored" do
      machines = [%{node: "ouro@build-box", machine: "ouro@build-box"}]
      assert Presentation.node_label("ouro@build-box", machines) == "ouro"
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
      expected = Presentation.refusal(:audit_disabled)

      assert expected =~ "Audit recording is disabled"

      for shape <- [
            {:error, :audit_disabled},
            {:error, -32_004, "Audit operation failed: :audit_disabled"},
            {:error, -32_004, "Audit operation failed: :audit_disabled", %{}},
            %{code: -32_004, message: "Audit operation failed: :audit_disabled"}
          ] do
        assert Presentation.refusal(shape) == expected, "#{inspect(shape)} read differently"
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

    test "a code embedded in a message is taken out of it" do
      assert Presentation.refusal("the fleet helper is unavailable (-32004)") ==
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
