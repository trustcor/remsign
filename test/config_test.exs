defmodule RemsignConfigTest do
  use ExUnit.Case

  test "no-op config canon" do
    assert Remsign.Config.config(%{}) == %{}
  end

  test "bad config" do
    assert Remsign.Config.config({:not, :valid}) == %{}
  end

  test "simple config" do
    c = %{ foo: 123, bar: [1, 2, 3]}
    assert Remsign.Config.config(c) == c
  end

  test "atomic config" do
    c = %{ "foo" => 123, "bar" => [1, 2, 3]}
    assert Remsign.Config.config(c) ==  %{ foo: 123, bar: [1, 2, 3]}
  end

  test "atomic recursive config" do
    c = %{
      "foo" => 123,
      "bar" => [1, 2, 3],
      "quux" => %{
        "foobar" => true,
        "baz" => :something
      }
    }
    assert Remsign.Config.config(c) ==  %{
      foo: 123,
      quux: %{
        foobar: true,
        baz: :something
      },
      bar: [1, 2, 3]}
  end

  test "readlines" do
    c = """
    one
      two
        three
    """
    assert Remsign.FileReader.readlines_s("dummy", {:ok, c}) == {:ok, ["one", "  two", "    three", ""]}
  end

  test "yaml config" do
    c = """
    ---
    foo: 123
    bar:
      - 1
      - 2
      - 3
    quux:
      foobar: true
      baz: something
    """
    assert Remsign.Config.config_yaml(c) ==  %{
      foo: 123,
      quux: %{
        foobar: true,
        baz: "something"
      },
      bar: [1, 2, 3]}
  end

  test "yaml file config" do
    {:ok, td} = Briefly.create(directory: true)
    on_exit fn -> File.rm_rf(td) end

    c3 = "foobar: true"
    File.write(Path.join(td, "incfile2.yml"), c3)
    c2 =  "bar: [1,2,3]"
    File.write!(Path.join(td, "incfile.yml"), c2)
    c1 = """
    foo: 123
    #include incfile.yml
    quux:
      #include incfile2.yml
      baz: something
    """
    cfile = Path.join(td, "config.yml")
    File.write!(cfile, c1)
    assert Remsign.Config.config_yaml_file(cfile) == %{
      foo: 123,
      quux: %{
        foobar: true,
        baz: "something"
      },
      bar: [1, 2, 3]
    }
  end

end
