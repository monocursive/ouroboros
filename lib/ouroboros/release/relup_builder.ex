defmodule Ouroboros.Release.RelupBuilder do
  @moduledoc """
  Offline `.relup` generation through OTP's `:systools`.

  `build/4` always supplies `:silent` and `:noexec`, so `:systools` returns the
  generated term and never writes a `relup` file. It reads the supplied `.rel`,
  `.app`, and `.appup` inputs from the code/search path. Mix itself does not
  generate relups; callers must prepare complete old and new release inputs.
  """

  alias Ouroboros.Release.Metadata

  @enforce_keys [:term, :encoded, :sha256, :warnings]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          term: term(),
          encoded: binary(),
          sha256: String.t(),
          warnings: list()
        }

  @spec build(
          Path.t(),
          [Path.t() | {Path.t(), term()}],
          [Path.t() | {Path.t(), term()}],
          keyword()
        ) ::
          {:ok, t()} | {:error, term()}
  def build(target_rel, upgrade_from, downgrade_to, opts \\ [])

  def build(target_rel, upgrade_from, downgrade_to, opts)
      when is_binary(target_rel) and is_list(upgrade_from) and is_list(downgrade_to) and
             is_list(opts) do
    with true <- Keyword.keyword?(opts) || {:error, :invalid_options},
         {:ok, target} <- normalize_rel_base(target_rel),
         {:ok, upgrades} <- normalize_rel_bases(upgrade_from),
         {:ok, downgrades} <- normalize_rel_bases(downgrade_to),
         {:ok, paths} <- normalize_paths(Keyword.get(opts, :path, [])),
         {:ok, result} <- make_relup(target, upgrades, downgrades, paths, opts),
         {:ok, _summary} <- Metadata.validate_relup(result.term) do
      encoded = Metadata.encode(result.term)

      {:ok,
       %__MODULE__{
         term: result.term,
         encoded: encoded,
         sha256: :crypto.hash(:sha256, encoded) |> Base.encode16(case: :lower),
         warnings: result.warnings
       }}
    end
  end

  def build(_target_rel, _upgrade_from, _downgrade_to, _opts),
    do: {:error, :invalid_relup_build}

  defp make_relup(target, upgrades, downgrades, paths, opts) do
    systools_opts = [:silent, :noexec, {:path, Enum.map(paths, &String.to_charlist/1)}]

    systools_opts =
      if Keyword.get(opts, :restart_emulator, false),
        do: [:restart_emulator | systools_opts],
        else: systools_opts

    systools_opts =
      if Keyword.get(opts, :warnings_as_errors, true),
        do: [:warnings_as_errors | systools_opts],
        else: systools_opts

    result =
      :systools.make_relup(
        String.to_charlist(target),
        Enum.map(upgrades, &external_base/1),
        Enum.map(downgrades, &external_base/1),
        systools_opts
      )

    case result do
      {:ok, term, _module, warnings} -> {:ok, %{term: term, warnings: warnings}}
      {:error, module, reason} -> {:error, {:relup_generation_failed, module, reason}}
      other -> {:error, {:relup_generation_failed, other}}
    end
  rescue
    error -> {:error, {:relup_generation_failed, error}}
  catch
    kind, reason -> {:error, {:relup_generation_failed, kind, reason}}
  end

  defp normalize_rel_bases(entries) do
    Enum.reduce_while(entries, {:ok, []}, fn
      {path, description}, {:ok, acc} when is_binary(path) ->
        case normalize_rel_base(path) do
          {:ok, base} -> {:cont, {:ok, [{base, description} | acc]}}
          {:error, _reason} = error -> {:halt, error}
        end

      path, {:ok, acc} when is_binary(path) ->
        case normalize_rel_base(path) do
          {:ok, base} -> {:cont, {:ok, [base | acc]}}
          {:error, _reason} = error -> {:halt, error}
        end

      invalid, _acc ->
        {:halt, {:error, {:invalid_release_base, invalid}}}
    end)
    |> case do
      {:ok, bases} -> {:ok, Enum.reverse(bases)}
      {:error, _reason} = error -> error
    end
  end

  defp normalize_rel_base(path) do
    expanded = Path.expand(path)

    base =
      if String.ends_with?(expanded, ".rel"), do: Path.rootname(expanded, ".rel"), else: expanded

    if File.regular?(base <> ".rel"),
      do: {:ok, base},
      else: {:error, {:release_file_unavailable, base <> ".rel"}}
  end

  defp normalize_paths(paths) when is_list(paths) do
    if Enum.all?(paths, &is_binary/1),
      do: {:ok, Enum.map(paths, &Path.expand/1)},
      else: {:error, :invalid_search_path}
  end

  defp normalize_paths(_paths), do: {:error, :invalid_search_path}

  defp external_base({base, description}), do: {String.to_charlist(base), description}
  defp external_base(base), do: String.to_charlist(base)
end
