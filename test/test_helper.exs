# `:live_native` tests call a real model provider and cost real money. They are excluded
# from `mix test` and run only when asked for by name:
#
#     OUROBOROS_NATIVE_MODEL=anthropic:claude-sonnet-5 mix test --include live_native
#
# The tests themselves are only defined when that variable is set, so an operator who
# keeps it exported still does not pay for a plain `mix test`.
#
# Distributed tests start `:net_kernel` on demand. A fresh VM does not start EPMD for
# that dynamic path, so make the suite independent of machine history and test order.
epmd = System.find_executable("epmd")

if is_nil(epmd) do
  raise "epmd is not on PATH; distributed tests need Erlang's port mapper"
end

case System.cmd(epmd, ["-daemon"], stderr_to_stdout: true) do
  {_output, 0} ->
    :ok

  {output, status} ->
    raise "could not start EPMD for distributed tests (exit #{status}): #{String.trim(output)}"
end

Enum.reduce_while(1..40, :error, fn attempt, _acc ->
  case System.cmd(epmd, ["-names"], stderr_to_stdout: true) do
    {_output, 0} ->
      {:halt, :ok}

    {output, status} when attempt == 40 ->
      raise "EPMD did not answer after startup (exit #{status}): #{String.trim(output)}"

    _not_ready ->
      Process.sleep(50)
      {:cont, :error}
  end
end)

# This suite is a Mix runtime, so `Ouroboros.Fleet.Deployment`'s `dev_runtime` blocker would
# otherwise be true for every case — and that blocker refuses a local `setup`, which is a
# path several suites have to be able to drive end to end. Declared packaged here so the
# default is the interesting one; the case that asks what a *dev* runtime answers deletes
# this key for its own duration and gets the runtime's own answer back.
Application.put_env(:ouroboros, :dev_runtime, false)

# `:real_worker` tests run the packaged `ouro` named by `OUROBOROS_TEST_OURO` as a real port
# program, which needs a build of the Rust side that speaks the frames front end. Excluded
# from `mix test` and run at integration once that slice lands:
#
#     OUROBOROS_TEST_OURO=/path/to/ouro mix test --include real_worker
ExUnit.start(exclude: [:live_native, :real_worker])
