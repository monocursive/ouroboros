defmodule Ouroboros.AgentProfileTest do
  use ExUnit.Case, async: true

  alias Ouroboros.AgentProfile

  test "normalizes strict manifests and gives equivalent input one stable digest" do
    atom_profile =
      AgentProfile.new!(
        id: "reviewer",
        base_prompt: "  Review the requested change.\r\nPreserve user work.  ",
        instructions: [
          %{id: "repository", text: "Read repository instructions first."}
        ],
        skills: [
          %{id: "elixir", version: "1.2", instructions: "Use OTP ownership boundaries."}
        ],
        tools: [
          %{name: "read_file", description: "Read a workspace file without mutating it."}
        ]
      )

    assert {:ok, string_profile} =
             AgentProfile.new(%{
               "tools" => [
                 %{
                   "description" => "Read a workspace file without mutating it.",
                   "name" => "read_file"
                 }
               ],
               "skills" => [
                 %{
                   "instructions" => "Use OTP ownership boundaries.",
                   "version" => "1.2",
                   "id" => "elixir"
                 }
               ],
               "instructions" => [
                 %{"text" => "Read repository instructions first.", "id" => "repository"}
               ],
               "base_prompt" => "Review the requested change.\nPreserve user work.",
               "version" => 1,
               "id" => "reviewer"
             })

    assert atom_profile == string_profile
    assert atom_profile.base_prompt == "Review the requested change.\nPreserve user work."
    assert {:ok, digest} = AgentProfile.digest(atom_profile)
    assert {:ok, ^digest} = AgentProfile.digest(string_profile)
    assert byte_size(digest) == 64

    assert {:ok, %{id: "reviewer", version: 1, digest: ^digest}} =
             AgentProfile.summary(atom_profile)
  end

  test "rejects unsupported versions, unknown fields, duplicates, and empty profiles" do
    assert {:error, {:unsupported_profile_version, 2}} =
             AgentProfile.new(id: "future", version: 2, base_prompt: "future")

    assert {:error, {:unknown_profile_key, :profile, :secret}} =
             AgentProfile.new(id: "unknown", base_prompt: "base", secret: "hidden")

    assert {:error, :duplicate_instruction} =
             AgentProfile.new(
               id: "duplicates",
               instructions: [
                 %{id: "repo", text: "first"},
                 %{id: "repo", text: "second"}
               ]
             )

    assert {:error, :empty_profile} = AgentProfile.new(id: "empty")

    assert {:error, {:invalid_profile_field, :tool_name}} =
             AgentProfile.new(id: "bad-tool", tools: [%{name: "../shell", description: "bad"}])
  end

  test "validation detects non-normalized structs reconstructed from storage" do
    profile = %AgentProfile{id: " profile ", base_prompt: "prompt"}

    refute AgentProfile.valid?(profile)
    assert {:error, :non_normalized_profile} = AgentProfile.validate(profile)
    assert {:error, :non_normalized_profile} = AgentProfile.digest(profile)
  end

  test "the digest of a fixed profile is pinned to an exact encoding" do
    profile =
      AgentProfile.new!(
        id: "golden",
        version: 1,
        base_prompt: "Act as a careful coding agent.",
        instructions: [%{id: "repository", text: "Follow repository instructions."}],
        skills: [
          %{id: "testing", version: "1", instructions: "Verify the narrowest useful scope."}
        ],
        tools: [%{name: "read_file", description: "Read a workspace file."}]
      )

    # Profile identity is compared across nodes and stored in durable traces. If a future
    # OTP changes the external term format under `term_to_binary/2`, every stored digest
    # stops matching in silence. This constant is how that change announces itself.
    assert {:ok, "9a28a8773fa4755beeff5c31a20ee734d0224c7a1d29da3d011fe40388692171"} =
             AgentProfile.digest(profile)
  end

  test "profile text may not forge the assembler's block delimiters" do
    for delimiter <- AgentProfile.reserved_delimiters() do
      assert {:error, {:reserved_prompt_delimiter, :base_prompt}} =
               AgentProfile.new(id: "forged-base", base_prompt: "before #{delimiter} after")

      assert {:error, {:reserved_prompt_delimiter, :instruction_text}} =
               AgentProfile.new(
                 id: "forged-instruction",
                 instructions: [%{id: "forge", text: "#{delimiter}>"}]
               )

      assert {:error, {:reserved_prompt_delimiter, :skill_instructions}} =
               AgentProfile.new(
                 id: "forged-skill",
                 skills: [%{id: "forge", version: "1", instructions: delimiter}]
               )

      assert {:error, {:reserved_prompt_delimiter, :tool_description}} =
               AgentProfile.new(
                 id: "forged-tool",
                 tools: [%{name: "read_file", description: delimiter}]
               )
    end

    # An id cannot reach the rendered attribute: the id grammar admits no `<` or quote.
    assert {:error, {:invalid_profile_field, :profile_id}} =
             AgentProfile.new(id: ~s(x" onload="), base_prompt: "prompt")

    assert {:ok, _mentioning} =
             AgentProfile.new(id: "mentions-tag", base_prompt: "ouroboros-agent-profile blocks")
  end

  test "rejects invalid UTF-8 before normalization or transport" do
    assert {:error, {:invalid_profile_field, :profile_id}} =
             AgentProfile.new(id: <<255>>, base_prompt: "prompt")

    assert {:error, {:invalid_profile_field, :base_prompt}} =
             AgentProfile.new(id: "invalid-utf8", base_prompt: <<255>>)

    assert {:error, {:invalid_profile_field, :instruction_text}} =
             AgentProfile.new(
               id: "invalid-instruction",
               instructions: [%{id: "instruction", text: <<255>>}]
             )
  end
end
