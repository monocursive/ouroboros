defmodule Ouroboros.RedactionTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Redaction

  test "redacts sensitive fields and embedded credential values without altering usage" do
    secret = "fixture-secret-value"

    value = %{
      "authorization" => "Bearer #{secret}",
      "nested" => %{"api-key" => secret, "message" => "value=#{secret}"},
      "input_tokens" => 42,
      "header" => "Bearer another-secret"
    }

    assert %{
             "authorization" => "[REDACTED]",
             "nested" => %{"api-key" => "[REDACTED]", "message" => "value=[REDACTED]"},
             "input_tokens" => 42,
             "header" => "Bearer [REDACTED]"
           } = Redaction.redact(value, [secret])
  end

  test "nested structs and lists redact keys while explicitly supplied secrets are longest first" do
    value = %{
      payload: [%{"client-secret" => "hidden", clientCredential: "visible"}],
      request: Ouroboros.Session.ApprovalResponse.new!(:approve),
      detail: "abcdef abc abcdefgh Bearer long-token; tail"
    }

    redacted = Redaction.redact(value, ["abc", "abcdef", "abcdefgh"])
    assert redacted.payload == [%{"client-secret" => "[REDACTED]", clientCredential: "visible"}]
    assert redacted.request.decision == :approve
    refute is_struct(redacted.request)
    assert redacted.detail == "[REDACTED] abc [REDACTED] Bearer [REDACTED]; tail"
    assert Redaction.redact(redacted) == redacted
  end
end
