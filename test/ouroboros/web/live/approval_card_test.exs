defmodule Ouroboros.Web.Live.ApprovalCardTest do
  @moduledoc """
  The card's three decisions, tested where they are pure.

  Which requests a rail row may answer, what a provider-offered option means, and whether
  a request carries a patch. The card's markup is asserted end to end in
  `Ouroboros.Web.Live.DeckLiveTest` against the golden corpus; this file is the part that
  has to hold for payloads the corpus does not carry — a vendor option this build has
  never seen, and an index a browser sent that the page never drew.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Web.Live.ApprovalCard
  alias Ouroboros.Web.Transcript.Approval

  defp request(payload), do: %Approval{request_id: "r1", sequence: 1, payload: payload}

  defp with_options(kinds) do
    request(%{
      "kind" => "permission",
      "tool_call" => %{"name" => "bash", "command" => "ls"},
      "options" =>
        Enum.with_index(kinds, fn kind, index ->
          %{"optionId" => "o#{index}", "name" => "option #{index}", "kind" => kind}
        end)
    })
  end

  describe "inline?/1" do
    test "a plain permission can be answered from a row" do
      assert ApprovalCard.inline?(
               request(%{"kind" => "permission", "tool_call" => %{"name" => "bash"}})
             )
    end

    test "a question, a plan exit and a Computer Use ask cannot" do
      refute ApprovalCard.inline?(request(%{"kind" => "question"}))
      refute ApprovalCard.inline?(request(%{"kind" => "plan_exit"}))

      refute ApprovalCard.inline?(
               request(%{"kind" => "permission", "tool_call" => %{"name" => "desktop_state"}})
             )

      refute ApprovalCard.inline?(
               request(%{"kind" => "permission", "tool_call" => %{"name" => "desktop_act"}})
             )
    end
  end

  describe "option_answer/2" do
    test "reads the locked decision table in the payload's own order" do
      offered = with_options(["allow_once", "allow_always", "reject_once", "reject_always"])

      assert ApprovalCard.option_answer(offered, 0) == {:approve, :once}
      assert ApprovalCard.option_answer(offered, 1) == {:approve, :session}
      assert ApprovalCard.option_answer(offered, 2) == {:deny, :once}
      assert ApprovalCard.option_answer(offered, 3) == {:deny, :session}
    end

    test "an option this build cannot read maps onto nothing" do
      # Guessing whether a novel vendor option approves or refuses is the one mistake that
      # cannot be undone, so it maps to `nil` and the card never gives it a button.
      assert ApprovalCard.option_answer(with_options(["teleport"]), 0) == nil
    end

    test "an index the page never drew answers nothing" do
      offered = with_options(["allow_once"])

      assert ApprovalCard.option_answer(offered, 7) == nil
      assert ApprovalCard.option_answer(offered, -1) == nil
    end
  end

  describe "parsed_diff/1" do
    test "is nil where the request carries no patch" do
      detail = Approval.detail(request(%{"kind" => "permission"}))

      assert ApprovalCard.parsed_diff(detail) == nil
    end

    test "counts from the hunk body rather than from the provider's claim" do
      detail =
        Approval.detail(
          request(%{
            "kind" => "write",
            "diff" => """
            --- a/lib/one.ex
            +++ b/lib/one.ex
            @@ -1,3 +1,4 @@
             kept
            -gone
            +new
            +also new
            """
          })
        )

      assert %{files: [file]} = ApprovalCard.parsed_diff(detail)
      assert file.path == "lib/one.ex"
      assert file.additions == 2
      assert file.deletions == 1
    end
  end
end
