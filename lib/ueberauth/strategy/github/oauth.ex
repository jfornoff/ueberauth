defmodule Ueberauth.Strategy.Github.OAuth do
  @moduledoc """
  An implementation of OAuth2 for github.

  To add your `client_id` and `client_secret` include these values in your configuration.

      config :ueberauth, Ueberauth.Strategy.Github.OAuth,
        client_id: System.get_env("GITHUB_CLIENT_ID"),
        client_secret: System.get_env("GITHUB_CLIENT_SECRET")
  """
  use OAuth2.Strategy

  alias OAuth2.{Client, Strategy}

  @ldefaults [
    strategy: __MODULE__,
    site: "https://api.github.com",
    authorize_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token"
  ]

  @doc """
  Construct a client for requests to Github.

  Optionally include any OAuth2 options here to be merged with the defaults.

      Ueberauth.Strategy.Github.OAuth.client(redirect_uri: "http://localhost:4000/auth/github/callback")

  This will be setup automatically for you in `Ueberauth.Strategy.Github`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    Client.new(opts ++ @defaults)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    ([token: token] ++ opts)
    |> client()
    |> put_param("client_secret", client().client_secret)
    |> Client.get(url, headers, opts)
  end

  def get_token!(params \\ [], options \\ []) do
    client_options = Keyword.drop(options, [:headers, :options])

    headers = Keyword.get(options, :headers, [])
    options = Keyword.get(options, :options, [])

    client_options
    |> client()
    |> Client.get_token!(params, headers, options)
    |> Map.get(:token)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> Strategy.AuthCode.get_token(params, headers)
  end
end
