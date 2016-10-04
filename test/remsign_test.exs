defmodule RemsignTest do
  use ExUnit.Case
  doctest Remsign

  @dummy_rsa_key """
  -----BEGIN PUBLIC KEY-----
  MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALV4FlkTutNoVCW4nrP7/+jGtEjZ6QUg
  51pfU9p7FBiK0Z/eN7/NoUAT7v/TgD3gatWpQ3ITPxojqV4jN8NrOAcCAwEAAQ==
  -----END PUBLIC KEY-----
  """

  @dummy_rsa_key2 """
  -----BEGIN PUBLIC KEY-----
  MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM+9A0ZDGr+34YWQGWxa6lMEgWv1p5+m
  WW29RE4mi/e3WeZmGA638+piOLBd+ZMi+jCCmXwk419DqCAmoOV3Kk0CAwEAAQ==
  -----END PUBLIC KEY-----
  """

  @dummy_ed25519_key """
  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPGkoKM+yMPJrNiinO08K0QH7rr7MIj8QMojgnRaTs3V
  """

  @dummy_ecdsa_key """
  ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNkH+Hs1IhbTmxvGf8Ag5Tnk9aN4v2gO1t0gNJDqDPKlWCHHW5PJS5/WCDKN3nJZxnDywtKq2SFdqxpeiCVXlDo=
  """

  import Remsign.Pubkey, only: [load_key: 1]
  import Remsign.Server, only: [canonical_name: 1]

  setup do
    bp = 20000
    {:ok, pa} = Agent.start_link(fn -> %{port: bp} end)
    cfg = %{
      base_port: bp,
      port_agent: pa,
      bind_addr: "127.0.0.1"
    }
    Remsign.Broker.start_link([])
    [cfg: cfg]
  end

  test "a new broker should have no state" do
    assert Remsign.Broker.state == %{dealers: %{}, keys: %{}}
  end

  test "register a new backend", context do
    lk = load_key(@dummy_rsa_key)
    kid = canonical_name(lk)

    assert Remsign.Broker.register(lk, context[:cfg]) == :ok
    rd = %Remsign.Server{name: kid, dealer_port: get_in(context, [:cfg, :base_port])}
    assert Remsign.Broker.state == %{dealers: %{ rd => MapSet.new([lk]) }, keys: %{ rsa: %{ kid => rd }}}
  end

  test "register two backends for same key", context do
    lk = load_key(@dummy_rsa_key)
    kid = canonical_name(lk)

    assert Remsign.Broker.register(lk, context[:cfg]) == :ok
    rd = %Remsign.Server{name: kid, dealer_port: get_in(context, [:cfg, :base_port])}

    assert Remsign.Broker.state == %{dealers: %{ rd => MapSet.new([lk])}, keys: %{ rsa: %{ kid => rd }}}
    assert Remsign.Broker.register(lk, context[:cfg]) == :ok
    assert Remsign.Broker.state ==
      %{
        dealers: %{ rd => MapSet.new([lk]) },
        keys: %{ rsa: %{kid => rd }}
      }
  end

  test "register two backends for different RSA keys", context do
    lk = load_key(@dummy_rsa_key)
    kid = canonical_name(lk)
    lk2 = load_key(@dummy_rsa_key2)
    kid2 = canonical_name(lk2)

    assert Remsign.Broker.register(lk, context[:cfg]) == :ok
    rd = %Remsign.Server{name: kid, dealer_port: get_in(context, [:cfg, :base_port])}
    rd2 = %Remsign.Server{name: kid2,  dealer_port: get_in(context, [:cfg, :base_port]) + 1}

    assert Remsign.Broker.state == %{dealers: %{ rd => MapSet.new([lk])}, keys: %{ rsa: %{ kid => rd }}}
    assert Remsign.Broker.register(lk2, context[:cfg]) == :ok
    assert Remsign.Broker.state ==
      %{dealers: %{
           rd => MapSet.new([lk]),
           rd2 => MapSet.new([lk2])},
        keys: %{ rsa: %{
                   kid => rd,
                   kid2 => rd2
                 }}}
  end

  test "register multiple backends for different key types", context do
    lk = load_key(@dummy_rsa_key)
    kid = canonical_name(lk)

    lk2 = load_key(@dummy_ed25519_key)
    kid2 = canonical_name(lk2)

    lk3 = load_key(@dummy_ecdsa_key)
    kid3 = canonical_name(lk3)

    rd = %Remsign.Server{name: kid, dealer_port: get_in(context, [:cfg, :base_port])}
    rd2 = %Remsign.Server{name: kid2, dealer_port: get_in(context, [:cfg, :base_port])+1}
    rd3 = %Remsign.Server{name: kid3, dealer_port: get_in(context, [:cfg, :base_port])+2}

    assert Remsign.Broker.register(lk, context[:cfg]) == :ok
    assert Remsign.Broker.register(lk2, context[:cfg]) == :ok
    assert Remsign.Broker.register(lk3, context[:cfg]) == :ok

    assert Remsign.Broker.state ==
      %{dealers: %{
           rd => MapSet.new([lk]),
           rd2 => MapSet.new([lk2]),
           rd3 => MapSet.new([lk3])
        },
        keys: %{ rsa: %{
                   kid => rd
                 },
                 ed25519: %{
                   kid2 => rd2
                 },
                 ecdsa: %{
                   kid3 => rd3
                 }
        }
       }
  end

  test "allocate single port", context do
    {port_alloc, dsock, _dpid} =  Remsign.Dealer.alloc(context[:cfg])
    assert port_alloc == 20000

    dest = context[:cfg][:bind_addr] |> String.to_charlist
    {:ok, sock} = :chumak.socket(:rep, 'test-ident')
    res = :chumak.connect(sock, :tcp, dest, 20000)
    assert elem(res, 0) == :ok
    :timer.sleep(5) # short wait to allow connection
    assert :chumak.send_multipart(dsock, ["", "test-ident|test-message"]) == :ok
    case :chumak.recv(sock) do
      {:ok, mpmsg} ->
        assert mpmsg == "test-ident|test-message"
      e ->
        assert e == :fail
    end
  end

end
