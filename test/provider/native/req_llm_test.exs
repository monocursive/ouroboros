defmodule Ouroboros.Provider.Native.Model.ReqLLMTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Model.ReqLLM

  test "normalizes the finite finish-reason vocabulary" do
    assert ReqLLM.normalize_finish_reason("stop") == :stop
    assert ReqLLM.normalize_finish_reason("completed") == :stop
    assert ReqLLM.normalize_finish_reason("tool_use") == :tool_calls
    assert ReqLLM.normalize_finish_reason("max_output_tokens") == :length
    assert ReqLLM.normalize_finish_reason("content_filter") == :content_filter
    assert ReqLLM.normalize_finish_reason(:cancelled) == :cancelled
    assert ReqLLM.normalize_finish_reason(:provider_extension) == :unknown
  end

  test "provider-defined finish reasons cannot allocate atoms" do
    reason = "provider_finish_reason_#{System.unique_integer([:positive])}"

    assert_raise ArgumentError, fn -> String.to_existing_atom(reason) end
    assert ReqLLM.normalize_finish_reason(reason) == :unknown

    assert_raise ArgumentError, fn -> String.to_existing_atom(reason) end
  end
end
