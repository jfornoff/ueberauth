defmodule Ueberauth.Strategy.Slack do
  @moduledoc """
  Implements an ÜeberauthSlack strategy for authentication with slack.com.

  When configuring the strategy in the Üeberauth providers, you can specify some defaults.

  * `uid_field` - The field to use as the UID field. This can be any populated field in the info struct. Default `:email`
  * `default_scope` - The scope to request by default from slack (permissions). Default "users:read"
  * `oauth2_module` - The OAuth2 module to use. Default Ueberauth.Strategy.Slack.OAuth

  ```elixir
  config :ueberauth, Ueberauth,
  providers: [
  slack: { Ueberauth.Strategy.Slack, [uid_field: :nickname, default_scope: "users:read,users:write"] }
  ]
  ```
  """

  @behaviour Ueberauth.Strategy

  @type challenge_params :: %{
    required(:callback_url) => String.t(),
    optional(:conn) => Plug.Conn.t(),
    optional(:scope) => String.t(),
    optional(:state) => String.t()
  }

  @type options :: [
    {:client_id, String.t()},
    {:client_secret, String.t()},
    {:oauth2_module, module},
    {:scope, String.t()},
    {:team, String.t()},
    {:uid_field, atom | (Auth.t() -> String.t())}
  ]

  @type authenticate_params :: %{
    required(:callback_url) => String.t(),
    optional(:conn) => Plug.Conn.t(),
    optional(:code) => String.t(),
    optional(:state) => String.t()
  }

  @default_scope "users:read"

  @defaults [
    uid_field: :email,
    scope: @default_scope,
    oauth2_module: __MODULE__.OAuth
  ]

  import Ueberauth.Strategy.Helpers

  alias Ueberauth.{
    Auth,
    Auth.Info,
    Auth.Credentials,
    Auth.Extra,
    Failure.Error
  }

  @impl true
  def authenticate(provider, %{conn: conn, query: %{"code" => _code} = params}, opts) do
    auth_url = request_uri(conn)
    auth_url = %{auth_url | query: nil}

    params =
      params
      |> map_string_to_atom([:state, :code])
      |> put_non_nil(:callback_url, to_string(auth_url))

    authenticate(provider, params, opts)
  end

  @impl true
  def authenticate(provider, %{code: _code, callback_url: _url} = params, opts) do
    opts
    |> Keyword.merge(@defaults)
    |> validate_options([:client_id, :client_secret])
    |> validation_result(provider, params)
  end

  def authenticate(provider, _, _opts) do
    {:error,
      create_failure(provider, __MODULE__, [
        error(:invalid_callback_params, "invalid callback params")
      ])}
  end

  @impl true
  def challenge(%{conn: conn} = params, opts) do
    opts = opts ++ @defaults
    scope = conn.params["scope"] || Keyword.get(opts, :default_scope, @default_scope)
    state = conn.params["state"] || Keyword.get(opts, :state)

    params
    |> put_non_nil(:scope, scope)
    |> put_non_nil(:state, state)
    |> put_non_nil(:team, Keyword.get(opts, :team))
    |> Map.drop([:conn])
    |> challenge(opts)
  end

  @impl true
  def challenge(%{callback_url: callback_url} = params, opts) do
    opts = opts ++ @defaults
    scopes = Map.get(params, :scope, Keyword.get(opts, :default_scope, @default_scope))
    params = Map.put(params, :scope, scopes)

    call_opts =
      params
      |> Map.take([:scope, :state, :team])
      |> Enum.into([])
      |> Keyword.put(:redirect_uri, callback_url)
      |> Keyword.put(:client_id, Keyword.get(opts, :client_id))

    module = Keyword.get(opts, :oauth2_module)

    case validate_options(call_opts, [:client_id, :redirect_uri]) do
      {:ok, copts} ->
        {:ok, copts |> module.authorize_url!(opts) |> URI.parse()}

      {:error, _reason} = err ->
        err
    end
  end

  def challenge(_, _), do: {:error, :invalid_params}

  @doc false
  def credentials(token, auth, user) do
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: not is_nil(token.expires_at),
      scopes: scopes,
      other: Map.merge(
        %{
          user: auth["user"],
          user_id: auth["user_id"],
          team: auth["team"],
          team_id: auth["team_id"],
          team_url: auth["url"]
        },
        user_credentials(user)
      )

    }
  end

  @doc false
  def extra(token, auth, user, team) do
    %Extra{
      raw_info: %{
        auth: auth,
        token: token,
        user: user,
        team: team
      }
    }
  end

  @doc false
  def info(auth, nil) do
    %{
      urls: %{
        team_url: auth["url"]
      }
    }
  end

  def info(auth, user) do
    profile = Map.get(user, "profile", %{})

    image_urls =
      profile
      |> Map.keys()
      |> Enum.filter(&(&1 =~ ~r/^image_/))
      |> Enum.into(%{}, &({&1, user["profile"][&1]}))

    %Info{
      name: name_from_user(user),
      nickname: user["name"],
      email: profile["email"],
      image: profile["image_48"],
      urls: Map.merge(
        image_urls,
        %{
          team_url: auth["url"],
        }
      )
    }
  end

  defp apply_uid(%Auth{} = auth, opts) do
    case Keyword.get(opts, :uid_field) do
      field when is_atom(field) ->
        %{auth | uid: Map.get(auth.info, field)}

      fun when is_function(fun) ->
        uid = fun.(auth)
        %{auth | uid: uid}
    end
  end

  defp construct_auth(provider, token, slack_auth, slack_user, slack_team, opts) do
    auth = %Auth{
      provider: provider,
      strategy: __MODULE__,
      credentials: credentials(token, slack_auth, slack_user),
      info: info(slack_auth, slack_user),
      extra: extra(token, slack_auth, slack_user, slack_team)
    }

    apply_uid(auth, opts)
  end

  defp fetch_auth(token) do
    with response <- Ueberauth.Strategy.Slack.OAuth.get(token, "/auth.test"),
         {:ok, body} <- handle_fetch_response(response),
      do: {:ok, body}
  end

  defp fetch_team(token, scopes) do
    with true <- "team:read" in scopes,
         response <- Ueberauth.Strategy.Slack.OAuth.get(token, "/team.info"),
         {:ok, %{"team" => team}} <- handle_fetch_response(response)
    do
      {:ok, team}
    else
      false -> {:ok, nil}
      err -> err
    end
  end

  defp fetch_user(token, %{"user_id" => user_id}, scopes) do
    with true <- "users:read" in scopes,
         response <- Ueberauth.Strategy.Slack.OAuth.get(token, "/users.info", %{user: user_id}),
         {:ok, %{"user" => user}} <- handle_fetch_response(response)
    do
      {:ok, user}
    else
      false -> {:ok, nil}
      err -> err
    end
  end

  defp get_token!(code, url, opts) do
    module = Keyword.get(opts, :oauth2_module)

    code
    |> put_non_nil(:redirect_uri, url)
    |> put_non_nil(:client_id, Keyword.get(opts, :client_id))
    |> put_non_nil(:client_secret, Keyword.get(opts, :client_secret))
    |> Enum.into([])
    |> module.get_token!(opts)
  end

  defp handle_fetch_response({:ok, %{status_code: status, body: %{"ok" => _} = body}}) when status in 200..399 do
    {:ok, body}
  end

  defp handle_fetch_response({:ok, %{body: %{"error" => error}}}) do
    {:error, error(error, error)}
  end

  defp handle_fetch_response({:ok, %{status_code: 401, body: _body}}) do
    {:error, error("token", "unauthorized")}
  end

  defp handle_fetch_response({:error, %{reason: reason}}) do
    {:error, error("OAuth2", reason)}
  end

  defp user_credentials(nil), do: %{}

  defp user_credentials(user) do
    %{
      has_2fa: user["has_2fa"],
      is_admin: user["is_admin"],
      is_owner: user["is_owner"],
      is_primary_owner: user["is_primary_owner"],
      is_restricted: user["is_restricted"],
      is_ultra_restricted: user["is_ultra_restricted"]
    }
  end

  # Fetch the name to use. We try to start with the most specific name avaialble and
  # fallback to the least.
  defp name_from_user(user) do
    [
      user["profile"]["real_name_normalized"],
      user["profile"]["real_name"],
      user["real_name"],
      user["name"]
    ]
    |> Enum.reject(&(&1 in ["", nil]))
    |> List.first()
  end

  defp validation_result({:ok, opts}, provider, %{code: code, callback_url: url}) do
    %{access_token: access_token, other_params: other_params} = token = get_token!(code, url, opts)

    with false <- is_nil(access_token),
         {:ok, slack_auth} <- fetch_auth(token),
         scope_string <- Map.get(other_params, "scope", ""),
         scopes <- String.split(scope_string, ","),
         {:ok, slack_user} <- fetch_user(token, slack_auth, scopes),
         {:ok, slack_team} <- fetch_team(token, scopes)
    do
      {:ok, construct_auth(provider, token, slack_auth, slack_user, slack_team, opts)}
    else
      true ->
        %{"error" => error, "error_description" => description} = other_params
        {:error, create_failure(provider, __MODULE__, [error(error, description)])}
    end
  end

  defp validation_result({:error, %Error{} = err}, provider, _params) do
    {:error, create_failure(provider, __MODULE__, [err])}
  end

  defp validation_result({:error, reason}, provider, _params) do
    create_failure(provider, __MODULE__, [error(reason, reason)])
  end
end
