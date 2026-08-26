defmodule Ouroboros.Provider.Native.Model.AdmissionTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Model.Admission

  setup do
    name = Module.concat(__MODULE__, "Server#{System.unique_integer([:positive])}")

    pid =
      start_supervised!({Admission, name: name, limit: 1, queue_limit: 1, queue_timeout_ms: 100})

    {:ok, server: name, pid: pid}
  end

  test "queues inside the explicit model boundary and grants after release", %{server: server} do
    assert {:ok, lease} = Admission.checkout(server)
    parent = self()

    waiter =
      spawn(fn ->
        send(parent, {:waiter, Admission.checkout(server)})
      end)

    assert_eventually(fn -> Admission.status(server).queued == 1 end)

    assert Admission.status(server) == %{
             active: 1,
             limit: 1,
             queued: 1,
             queue_limit: 1,
             queue_timeout_ms: 100
           }

    :ok = Admission.release(lease)
    assert_receive {:waiter, {:ok, next_lease}}, 200
    assert Process.alive?(waiter) == false
    :ok = Admission.release(next_lease)
    assert Admission.status(server).active == 0
  end

  test "bounds the queue and gives timeout and saturation distinct errors", %{
    server: server,
    pid: pid
  } do
    assert {:ok, lease} = Admission.checkout(server)
    parent = self()

    spawn(fn -> send(parent, {:timed_out, Admission.checkout(server)}) end)
    assert_eventually(fn -> Admission.status(server).queued == 1 end)

    assert {:error, {:model_capacity_exhausted, %{limit: 1, queue_limit: 1}}} =
             Admission.checkout(server)

    assert_receive {:timed_out, {:error, {:model_capacity_timeout, %{limit: 1, waited_ms: 100}}}},
                   250

    assert Admission.status(server).queued == 0
    assert queue_empty?(pid)

    :ok = Admission.release(lease)
    assert {:ok, next_lease} = Admission.checkout(server)
    :ok = Admission.release(next_lease)
    assert Admission.status(server).active == 0
    assert queue_empty?(pid)
  end

  test "an owner crash releases its lease and wakes the next caller", %{server: server} do
    parent = self()

    owner =
      spawn(fn ->
        {:ok, _lease} = Admission.checkout(server)
        send(parent, :owner_ready)
        Process.sleep(:infinity)
      end)

    assert_receive :owner_ready
    spawn(fn -> send(parent, {:replacement, Admission.checkout(server)}) end)
    assert_eventually(fn -> Admission.status(server).queued == 1 end)

    Process.exit(owner, :kill)
    assert_receive {:replacement, {:ok, replacement}}, 200
    :ok = Admission.release(replacement)
  end

  test "a leased stream releases on completion, early halt, and exception", %{server: server} do
    assert {:ok, stream} = Admission.with_stream(fn -> {:ok, 1..3} end, server)
    assert Enum.to_list(stream) == [1, 2, 3]
    assert Admission.status(server).active == 0

    assert {:ok, stream} = Admission.with_stream(fn -> {:ok, Stream.cycle([:item])} end, server)
    assert Enum.take(stream, 1) == [:item]
    assert Admission.status(server).active == 0

    raising = Stream.map([:item], fn _ -> raise "stream broke" end)
    assert {:ok, stream} = Admission.with_stream(fn -> {:ok, raising} end, server)
    assert_raise RuntimeError, "stream broke", fn -> Enum.to_list(stream) end
    assert Admission.status(server).active == 0
  end

  test "a waiter crash frees its queue slot without leaving a ghost", %{server: server, pid: pid} do
    assert {:ok, lease} = Admission.checkout(server)

    waiter =
      spawn(fn ->
        Admission.checkout(server)
        Process.sleep(:infinity)
      end)

    assert_eventually(fn -> Admission.status(server).queued == 1 end)
    Process.exit(waiter, :kill)
    assert_eventually(fn -> Admission.status(server).queued == 0 end)
    assert queue_empty?(pid)

    parent = self()
    spawn(fn -> send(parent, {:replacement, Admission.checkout(server)}) end)
    assert_eventually(fn -> Admission.status(server).queued == 1 end)

    :ok = Admission.release(lease)
    assert_receive {:replacement, {:ok, replacement}}, 200
    :ok = Admission.release(replacement)
    assert queue_empty?(pid)
  end

  test "constructor errors and invalid returns release immediately", %{server: server} do
    assert {:error, :nope} = Admission.with_stream(fn -> {:error, :nope} end, server)
    assert Admission.status(server).active == 0

    assert {:error, {:invalid_stream, :oops}} = Admission.with_stream(fn -> :oops end, server)
    assert Admission.status(server).active == 0
  end

  test "checkout names an unavailable server instead of exiting", %{server: server} do
    :ok = stop_supervised(Admission)

    assert {:error, {:model_admission_unavailable, _reason}} = Admission.checkout(server)
  end

  defp queue_empty?(pid) do
    pid |> :sys.get_state() |> Map.fetch!(:queue) |> :queue.is_empty()
  end

  defp assert_eventually(fun, attempts \\ 40)

  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(5)
      assert_eventually(fun, attempts - 1)
    end
  end
end
