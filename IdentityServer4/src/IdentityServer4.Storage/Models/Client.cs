// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Generic;
using System.Linq;
using System;
using System.Collections;
using System.Diagnostics;

namespace IdentityServer4.Models
{
    /// <summary>
    /// Models an OpenID Connect or OAuth2 client
    /// OpenID Connect / OAuth2 客户端
    /// </summary>
    [DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
    public class Client
    {
        // setting grant types should be atomic
        private ICollection<string> _allowedGrantTypes = new GrantTypeValidatingHashSet();

        private string DebuggerDisplay => ClientId ?? $"{{{typeof(Client)}}}";

        /// <summary>
        /// Specifies if client is enabled (defaults to <c>true</c>)
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// 一个唯一的客户端ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// 协议类型，固定值为oidc
        /// </summary>
        /// <value>
        /// The protocol type.
        /// </value>
        public string ProtocolType { get; set; } = IdentityServerConstants.ProtocolTypes.OpenIdConnect;

        /// <summary>
        /// Client secrets - only relevant for flows that require a secret
        /// 客户端secret列表，访问令牌端点的凭据。RequireClientSecret为true时必填。
        /// </summary>
        public ICollection<Secret> ClientSecrets { get; set; } = new HashSet<Secret>();

        /// <summary>
        /// If set to false, no client secret is needed to request tokens at the token endpoint (defaults to <c>true</c>)
        /// 获取token时是否需要client secret，默认为true，使用js客户端模式时可以设置为false
        /// </summary>
        public bool RequireClientSecret { get; set; } = true;

        /// <summary>
        /// 客户端显示名称(用于记录和Consent页面显示)
        /// </summary>
        public string ClientName { get; set; }

        /// <summary>
        /// 客户端的描述信息
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// URI to further information about client (used on consent screen)
        /// 有关客户端的更多信息的URI（在Consent页面上使用）
        /// </summary>
        public string ClientUri { get; set; }

        /// <summary>
        /// URI to client logo (used on consent screen)
        /// 有关客户端Logo地址（在Consent页面上使用）
        /// </summary>
        public string LogoUri { get; set; }

        /// <summary>
        /// Specifies whether a consent screen is required (defaults to <c>false</c>)
        /// 指定是否需要Consent页。默认为false。
        /// </summary>
        public bool RequireConsent { get; set; } = false;

        /// <summary>
        /// Specifies whether user can choose to store consent decisions (defaults to <c>true</c>)
        /// 是否允许记住用户Consent夜的确认授权的结果
        /// </summary>
        public bool AllowRememberConsent { get; set; } = true;

        /// <summary>
        /// Specifies the allowed grant types (legal combinations of AuthorizationCode, Implicit, Hybrid, ResourceOwner, ClientCredentials).
        /// 允许与令牌服务的交互（称为授权类型）
        /// </summary>
        public ICollection<string> AllowedGrantTypes
        {
            get { return _allowedGrantTypes; }
            set
            {
                ValidateGrantTypes(value);
                _allowedGrantTypes = new GrantTypeValidatingHashSet(value);
            }
        }

        /// <summary>
        /// Specifies whether a proof key is required for authorization code based token requests (defaults to <c>true</c>).
        /// 指定使用基于授权代码的授权类型的客户端是否必须发送校验密钥。
        /// </summary>
        public bool RequirePkce { get; set; } = true;

        /// <summary>
        /// Specifies whether a proof key can be sent using plain method (not recommended and defaults to <c>false</c>.)
        /// 指定使用PKCE的客户端是否可以使用蠢文本代码质询(不推荐-默认为false)
        /// </summary>
        public bool AllowPlainTextPkce { get; set; } = false;

        /// <summary>
        /// Specifies whether the client must use a request object on authorize requests (defaults to <c>false</c>.)
        /// 访问控制Authorize节点时，参数是作为普通的url参数，还是作为一个jwt对象传输，职责杨可以防止篡改参数。
        /// </summary>
        public bool RequireRequestObject { get; set; } = false;
        
        /// <summary>
        /// Controls whether access tokens are transmitted via the browser for this client (defaults to <c>false</c>).
        /// This can prevent accidental leakage of access tokens when multiple response types are allowed.
        /// 指定是否允许此客户端通过浏览器接收访问令牌
        /// </summary>
        /// <value>
        /// <c>true</c> if access tokens can be transmitted via the browser; otherwise, <c>false</c>.
        /// </value>
        public bool AllowAccessTokensViaBrowser { get; set; } = false;

        /// <summary>
        /// Specifies allowed URIs to return tokens or authorization codes to
        /// 指定允许的URIs以返回tokens或授权codes
        /// </summary>
        public ICollection<string> RedirectUris { get; set; } = new HashSet<string>();

        /// <summary>
        /// Specifies allowed URIs to redirect to after logout
        /// 指定在注销后重定向到的允许URI。
        /// </summary>
        public ICollection<string> PostLogoutRedirectUris { get; set; } = new HashSet<string>();

        /// <summary>
        /// Specifies logout URI at client for HTTP front-channel based logout.
        /// 指定客户端的注销URI,以用于基于HTTP的前端通道注销。
        /// </summary>
        public string FrontChannelLogoutUri { get; set; }

        /// <summary>
        /// Specifies is the user's session id should be sent to the FrontChannelLogoutUri. Defaults to <c>true</c>.
        /// 指定是否应该将用户的会话ID发送到FrontChannelLogoutUri。默认为True
        /// </summary>
        public bool FrontChannelLogoutSessionRequired { get; set; } = true;

        /// <summary>
        /// Specifies logout URI at client for HTTP back-channel based logout.
        /// 指定客户端的注销URI，以用于基于HTTP的反向通道注销。
        /// </summary>
        public string BackChannelLogoutUri { get; set; }

        /// <summary>
        /// Specifies is the user's session id should be sent to the BackChannelLogoutUri. Defaults to <c>true</c>.
        /// 指定是否应在请求中奖用户的会话ID发送到BackChannelLogoutUri。默认为true
        /// </summary>
        public bool BackChannelLogoutSessionRequired { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether [allow offline access]. Defaults to <c>false</c>.
        /// 指定此客户端是否可以请求刷新令牌(请求scope需要包含 offine access)
        /// </summary>
        public bool AllowOfflineAccess { get; set; } = false;

        /// <summary>
        /// Specifies the api scopes that the client is allowed to request. If empty, the client can't access any scope
        /// 允许客户端访问的Scope列表（API资源）
        /// </summary>
        public ICollection<string> AllowedScopes { get; set; } = new HashSet<string>();

        /// <summary>
        /// When requesting both an id token and access token, should the user claims always be added to the id token instead of requiring the client to use the userinfo endpoint.
        /// Defaults to <c>false</c>.
        /// 在请求id token和access token时，如果始终将用户声明(user claims)添加到id token而不是请求客户端使用的userinfo endpoint.默认为false
        /// </summary>
        public bool AlwaysIncludeUserClaimsInIdToken { get; set; } = false;

        /// <summary>
        /// Lifetime of identity token in seconds (defaults to 300 seconds / 5 minutes)
        /// Identity token的有效期，以秒为单位(默认300秒=5分钟)。
        /// </summary>
        public int IdentityTokenLifetime { get; set; } = 300;

        /// <summary>
        /// Signing algorithm for identity token. If empty, will use the server default signing algorithm.
        /// 允许id token的签名算法，为空则使用默认的签名。
        /// </summary>
        public ICollection<string> AllowedIdentityTokenSigningAlgorithms { get; set; } = new HashSet<string>();

        /// <summary>
        /// Lifetime of access token in seconds (defaults to 3600 seconds / 1 hour)
        /// 访问令牌的生命周期，以秒为单位(默认为3600秒/1小时)
        /// </summary>
        public int AccessTokenLifetime { get; set; } = 3600;

        /// <summary>
        /// Lifetime of authorization code in seconds (defaults to 300 seconds / 5 minutes)
        /// 授权码(code)的生命周期，以秒为单位。(默认300秒=5分钟)。
        /// </summary>
        public int AuthorizationCodeLifetime { get; set; } = 300;

        /// <summary>
        /// Maximum lifetime of a refresh token in seconds. Defaults to 2592000 seconds / 30 days
        /// 刷新令牌的最长生命周期，以秒为单位。默认2592000秒/30天
        /// </summary>
        public int AbsoluteRefreshTokenLifetime { get; set; } = 2592000;

        /// <summary>
        /// Sliding lifetime of a refresh token in seconds. Defaults to 1296000 seconds / 15 days
        /// 滑动刷新令牌的生命周期，以秒为单位。默认为1296000妙/15天
        /// </summary>
        public int SlidingRefreshTokenLifetime { get; set; } = 1296000;

        /// <summary>
        /// Lifetime of a user consent in seconds. Defaults to null (no expiration)
        /// 用户授权确认结果的生命周期，以秒为单位。默认为null(无到期)
        /// </summary>
        public int? ConsentLifetime { get; set; } = null;

        /// <summary>
        /// ReUse: the refresh token handle will stay the same when refreshing tokens
        /// OneTime: the refresh token handle will be updated when refreshing tokens
        /// 刷新令牌用法，0-ReUse刷新令牌时，刷新令牌句柄将保持不变。1-OneTime刷新令牌时将更新刷新令牌句柄。
        /// </summary>
        public TokenUsage RefreshTokenUsage { get; set; } = TokenUsage.OneTimeOnly;

        /// <summary>
        /// Gets or sets a value indicating whether the access token (and its claims) should be updated on a refresh token request.
        /// Defaults to <c>false</c>.
        /// 获取或设置一个值，该值指示是否应在刷新令牌请求上更新访问令牌(以及其声明)
        /// </summary>
        /// <value>
        /// <c>true</c> if the token should be updated; otherwise, <c>false</c>.
        /// </value>
        public bool UpdateAccessTokenClaimsOnRefresh { get; set; } = false;

        /// <summary>
        /// Absolute: the refresh token will expire on a fixed point in time (specified by the AbsoluteRefreshTokenLifetime)
        /// Sliding: when refreshing the token, the lifetime of the refresh token will be renewed (by the amount specified in SlidingRefreshTokenLifetime). The lifetime will not exceed AbsoluteRefreshTokenLifetime.
        /// 刷新令牌过期类型，0-Absolute刷新令牌将在固定时间点到期(由AbsoluteRefreshTokenLifetime指定)
        /// 1-Sliding刷新令牌时，将刷新刷新令牌的生命周期(按SlidingRefreshTokenLifetime中指定的数量。)
        /// 生命这周起不会超过AbsoluteRefreshTokenLifetime.
        /// </summary>        
        public TokenExpiration RefreshTokenExpiration { get; set; } = TokenExpiration.Absolute;

        /// <summary>
        /// Specifies whether the access token is a reference token or a self contained JWT token (defaults to Jwt).
        /// 指定访问令牌是引用令牌还是自包含JWT令牌，0-Jwt;JWT令牌、1-Reference:引用令牌。(默认为Jwt)
        /// </summary>
        public AccessTokenType AccessTokenType { get; set; } = AccessTokenType.Jwt;

        /// <summary>
        /// Gets or sets a value indicating whether the local login is allowed for this client. Defaults to <c>true</c>.
        /// 指定此客户端是否可以仅使用本地账户或外部IDP(Identity Provider)。默认为true
        /// </summary>
        /// <value>
        ///   <c>true</c> if local logins are enabled; otherwise, <c>false</c>.
        /// </value>
        public bool EnableLocalLogin { get; set; } = true;

        /// <summary>
        /// Specifies which external IdPs can be used with this client (if list is empty all IdPs are allowed). Defaults to empty.
        /// 指定客户端可使用的扩展Idp(Identity Provider)
        /// </summary>
        public ICollection<string> IdentityProviderRestrictions { get; set; } = new HashSet<string>();

        /// <summary>
        /// Gets or sets a value indicating whether JWT access tokens should include an identifier. Defaults to <c>true</c>.
        /// 指定JWT访问令牌是否应具有嵌入的唯一ID（通过JWT声明）
        /// </summary>
        /// <value>
        /// <c>true</c> to add an id; otherwise, <c>false</c>.
        /// </value>
        public bool IncludeJwtId { get; set; } = true;

        /// <summary>
        /// Allows settings claims for the client (will be included in the access token).
        /// 在此属性上设置的值将会被直接添加到AccessToken
        /// </summary>
        /// <value>
        /// The claims.
        /// </value>
        public ICollection<ClientClaim> Claims { get; set; } = new HashSet<ClientClaim>();

        /// <summary>
        /// Gets or sets a value indicating whether client claims should be always included in the access tokens - or only for client credentials flow.
        /// Defaults to <c>false</c>
        /// 如果设置，将为每个流发送客户端声明。如果不是，仅用于客户端凭证流(默认为false)
        /// </summary>
        /// <value>
        /// <c>true</c> if claims should always be sent; otherwise, <c>false</c>.
        /// </value>
        public bool AlwaysSendClientClaims { get; set; } = false;

        /// <summary>
        /// Gets or sets a value to prefix it on client claim types. Defaults to <c>client_</c>.
        /// 如果设置，将以前缀为前缀客户端声明类型。默认为client_,目的是确保他们不会意外的与用户声明冲突。
        /// </summary>
        /// <value>
        /// Any non empty string if claims should be prefixed with the value; otherwise, <c>null</c>.
        /// </value>
        public string ClientClaimsPrefix { get; set; } = "client_";

        /// <summary>
        /// Gets or sets a salt value used in pair-wise subjectId generation for users of this client.
        /// 对于此客户端的用户，在成对的subjectId生成中使用的salt值。
        /// </summary>
        public string PairWiseSubjectSalt { get; set; }

        /// <summary>
        /// The maximum duration (in seconds) since the last time the user authenticated.
        /// 自上次用户进行身份验证以来的最长持续时间(以秒为单位)。默认为null。您可以调整会话令牌的生命周期，
        /// 以控制在使用Web应用程序时，用户需要重新输入凭据的时间和频率，而不是进行静默身份验证。
        /// </summary>
        public int? UserSsoLifetime { get; set; }

        /// <summary>
        /// Gets or sets the type of the device flow user code.
        /// </summary>
        /// <value>
        /// The type of the device flow user code.
        /// </value>
        public string UserCodeType { get; set; }

        /// <summary>
        /// Gets or sets the device code lifetime.
        /// </summary>
        /// <value>
        /// The device code lifetime.
        /// </value>
        public int DeviceCodeLifetime { get; set; } = 300;

        /// <summary>
        /// Gets or sets the allowed CORS origins for JavaScript clients.
        /// 用于为JavaScripts客户端构建CORS策略
        /// </summary>
        /// <value>
        /// The allowed CORS origins.
        /// </value>
        public ICollection<string> AllowedCorsOrigins { get; set; } = new HashSet<string>();

        /// <summary>
        /// Gets or sets the custom properties for the client.
        /// </summary>
        /// <value>
        /// The properties.
        /// </value>
        public IDictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Validates the grant types.
        /// </summary>
        /// <param name="grantTypes">The grant types.</param>
        /// <exception cref="System.InvalidOperationException">
        /// Grant types list is empty
        /// or
        /// Grant types cannot contain spaces
        /// or
        /// Grant types list contains duplicate values
        /// </exception>
        public static void ValidateGrantTypes(IEnumerable<string> grantTypes)
        {
            if (grantTypes == null)
            {
                throw new ArgumentNullException(nameof(grantTypes));
            }

            // spaces are not allowed in grant types
            foreach (var type in grantTypes)
            {
                if (type.Contains(' '))
                {
                    throw new InvalidOperationException("Grant types cannot contain spaces");
                }
            }

            // single grant type, seems to be fine
            if (grantTypes.Count() == 1) return;

            // don't allow duplicate grant types
            if (grantTypes.Count() != grantTypes.Distinct().Count())
            {
                throw new InvalidOperationException("Grant types list contains duplicate values");
            }

            // would allow response_type downgrade attack from code to token
            DisallowGrantTypeCombination(GrantType.Implicit, GrantType.AuthorizationCode, grantTypes);
            DisallowGrantTypeCombination(GrantType.Implicit, GrantType.Hybrid, grantTypes);

            DisallowGrantTypeCombination(GrantType.AuthorizationCode, GrantType.Hybrid, grantTypes);
        }

        private static void DisallowGrantTypeCombination(string value1, string value2, IEnumerable<string> grantTypes)
        {
            if (grantTypes.Contains(value1, StringComparer.Ordinal) &&
                grantTypes.Contains(value2, StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"Grant types list cannot contain both {value1} and {value2}");
            }
        }

        internal class GrantTypeValidatingHashSet : ICollection<string>
        {
            private readonly ICollection<string> _inner;

            public GrantTypeValidatingHashSet()
            {
                _inner = new HashSet<string>();
            }

            public GrantTypeValidatingHashSet(IEnumerable<string> values)
            {
                _inner = new HashSet<string>(values);
            }

            private ICollection<string> Clone()
            {
                return new HashSet<string>(this);
            }

            private ICollection<string> CloneWith(params string[] values)
            {
                var clone = Clone();
                foreach (var item in values) clone.Add(item);
                return clone;
            }

            public int Count => _inner.Count;

            public bool IsReadOnly => _inner.IsReadOnly;

            public void Add(string item)
            {
                ValidateGrantTypes(CloneWith(item));
                _inner.Add(item);
            }

            public void Clear()
            {
                _inner.Clear();
            }

            public bool Contains(string item)
            {
                return _inner.Contains(item);
            }

            public void CopyTo(string[] array, int arrayIndex)
            {
                _inner.CopyTo(array, arrayIndex);
            }

            public IEnumerator<string> GetEnumerator()
            {
                return _inner.GetEnumerator();
            }

            public bool Remove(string item)
            {
                return _inner.Remove(item);
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return _inner.GetEnumerator();
            }
        }
    }
}
