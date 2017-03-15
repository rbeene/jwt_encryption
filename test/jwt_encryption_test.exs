defmodule JwtEncryptionTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Plug.Conn
  doctest JwtEncryption

  defmodule DemoPlug do
    use Plug.Builder

    plug JwtEncryption
  end

  test "decrypting Bearer authorization tokens set token to decrypted value" do
    encrypted = encrypted_token()
    conn = conn(:get, "/")
    |> put_req_header("authorization", "Bearer: #{encrypted}")
    |> DemoPlug.call([])

    [authorization] = conn |> get_req_header("authorization")

    assert authorization == "Bearer: #{decrypted_token()}"
  end

  test "encrypt" do
    signature = decrypted_token()
               |> JwtEncryption.encrypt()

    assert JwtEncryption.decrypt(signature) == decrypted_token()
  end

  defp encrypted_token() do
    decrypted_token()
    |> JwtEncryption.encrypt
  end

  defp decrypted_token() do
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
  end

end
