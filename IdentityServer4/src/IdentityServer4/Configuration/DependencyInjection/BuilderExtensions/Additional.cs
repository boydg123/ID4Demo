// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Net.Http;
using IdentityServer4;
using IdentityServer4.Configuration;
using Microsoft.Extensions.Logging;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Builder extension methods for registering additional services 
    /// </summary>
    public static class IdentityServerBuilderExtensionsAdditional
    {
        /// <summary>
        /// Adds the extension grant validator.
        /// 添加用于扩展授权的IExtensionGrantValidator实现。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddExtensionGrantValidator<T>(this IIdentityServerBuilder builder)
            where T : class, IExtensionGrantValidator
        {
            builder.Services.AddTransient<IExtensionGrantValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds a redirect URI validator.
        /// 添加IRedirectUriValidator实现来自定义重定向URI验证。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddRedirectUriValidator<T>(this IIdentityServerBuilder builder)
            where T : class, IRedirectUriValidator
        {
            builder.Services.AddTransient<IRedirectUriValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds a an "AppAuth" (OAuth 2.0 for Native Apps) compliant redirect URI validator (does strict validation but also allows http://127.0.0.1 with random port)
        /// 添加一个“AppAuth”（OAuth 2.0 for Native Apps）兼容的重定向URI验证器（进行严格的验证，但也允许随机端口为http://127.0.0.1）。
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddAppAuthRedirectUriValidator(this IIdentityServerBuilder builder)
        {
            return builder.AddRedirectUriValidator<StrictRedirectUriValidatorAppAuth>();
        }

        /// <summary>
        /// Adds the resource owner validator.
        /// 添加IResourceOwnerPasswordValidator`实现，用于验证资源所有者密码凭据授权类型的用户凭证
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddResourceOwnerValidator<T>(this IIdentityServerBuilder builder)
           where T : class, IResourceOwnerPasswordValidator
        {
            builder.Services.AddTransient<IResourceOwnerPasswordValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds the profile service.
        /// 添加IProfileService以实现连接到您的自定义用户配置文件存储。
        /// DefaultProfileService`类提供了默认实现，它依靠身份验证cookie作为唯一的令牌发放源。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddProfileService<T>(this IIdentityServerBuilder builder)
           where T : class, IProfileService
        {
            builder.Services.AddTransient<IProfileService, T>();

            return builder;
        }
        
        /// <summary>
        /// Adds a resource validator.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddResourceValidator<T>(this IIdentityServerBuilder builder)
            where T : class, IResourceValidator
        {
            builder.Services.AddTransient<IResourceValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds a scope parser.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddScopeParser<T>(this IIdentityServerBuilder builder)
            where T : class, IScopeParser
        {
            builder.Services.AddTransient<IScopeParser, T>();

            return builder;
        }

        /// <summary>
        /// Adds a client store.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddClientStore<T>(this IIdentityServerBuilder builder)
           where T : class, IClientStore
        {
            builder.Services.TryAddTransient(typeof(T));
            builder.Services.AddTransient<IClientStore, ValidatingClientStore<T>>();

            return builder;
        }

        /// <summary>
        /// Adds a resource store.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddResourceStore<T>(this IIdentityServerBuilder builder)
           where T : class, IResourceStore
        {
            builder.Services.AddTransient<IResourceStore, T>();

            return builder;
        }

        /// <summary>
        /// Adds a device flow store.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        public static IIdentityServerBuilder AddDeviceFlowStore<T>(this IIdentityServerBuilder builder)
            where T : class, IDeviceFlowStore
        {
            builder.Services.AddTransient<IDeviceFlowStore, T>();

            return builder;
        }

        /// <summary>
        /// Adds a persisted grant store.
        /// </summary>
        /// <typeparam name="T">The type of the concrete grant store that is registered in DI.</typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns>The builder.</returns>
        public static IIdentityServerBuilder AddPersistedGrantStore<T>(this IIdentityServerBuilder builder)
            where T : class, IPersistedGrantStore
        {
            builder.Services.AddTransient<IPersistedGrantStore, T>();

            return builder;
        }

        /// <summary>
        /// Adds a CORS policy service.
        /// </summary>
        /// <typeparam name="T">The type of the concrete scope store class that is registered in DI.</typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddCorsPolicyService<T>(this IIdentityServerBuilder builder)
            where T : class, ICorsPolicyService
        {
            builder.Services.AddTransient<ICorsPolicyService, T>();
            return builder;
        }

        /// <summary>
        /// Adds a CORS policy service cache.
        /// 注册一个ICorsPolicyService装饰器实现，它将维护一个CORS策略服务评估结果的内存缓存。
        /// 缓存持续时间可以在IdentityServerOptions上的缓存配置选项上配置。
        /// </summary>
        /// <typeparam name="T">The type of the concrete CORS policy service that is registered in DI.</typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddCorsPolicyCache<T>(this IIdentityServerBuilder builder)
            where T : class, ICorsPolicyService
        {
            builder.Services.TryAddTransient(typeof(T));
            builder.Services.AddTransient<ICorsPolicyService, CachingCorsPolicyService<T>>();
            return builder;
        }

        /// <summary>
        /// Adds the secret parser.
        /// 添加用于解析客户端或API资源凭证的ISecretParser实现。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddSecretParser<T>(this IIdentityServerBuilder builder)
            where T : class, ISecretParser
        {
            builder.Services.AddTransient<ISecretParser, T>();

            return builder;
        }

        /// <summary>
        /// Adds the secret validator.
        /// 添加ISecretValidator实现，以针对凭证存储验证客户端或API资源凭证。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddSecretValidator<T>(this IIdentityServerBuilder builder)
            where T : class, ISecretValidator
        {
            builder.Services.AddTransient<ISecretValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds the client store cache.
        /// 注册一个IClientStore装饰器实现，它将维护客户端配置对象的内存缓存。 缓存持续时间可以在IdentityServerOptions上的缓存配置选项上配置。
        /// </summary>
        /// <typeparam name="T">The type of the concrete client store class that is registered in DI.</typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddClientStoreCache<T>(this IIdentityServerBuilder builder)
            where T : IClientStore
        {
            builder.Services.TryAddTransient(typeof(T));
            builder.Services.AddTransient<ValidatingClientStore<T>>();
            builder.Services.AddTransient<IClientStore, CachingClientStore<ValidatingClientStore<T>>>();

            return builder;
        }

        /// <summary>
        /// Adds the client store cache.
        /// 注册一个IResourceStore装饰器实现，它将维护IdentityResource和ApiResource配置对象的内存缓存。
        /// 缓存持续时间可以在IdentityServerOptions上的缓存配置选项上配置。
        /// </summary>
        /// <typeparam name="T">The type of the concrete scope store class that is registered in DI.</typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddResourceStoreCache<T>(this IIdentityServerBuilder builder)
            where T : IResourceStore
        {
            builder.Services.TryAddTransient(typeof(T));
            builder.Services.AddTransient<IResourceStore, CachingResourceStore<T>>();
            return builder;
        }

        /// <summary>
        /// Adds the authorize interaction response generator.
        /// 添加IAuthorizeInteractionResponseGenerator实现来在授权端点定制逻辑，以便显示用户错误，登录，同意或任何其他自定义页面的UI。
        /// AuthorizeInteractionResponseGenerator类提供了一个默认的实现，因此如果需要增加现有的行为，可以考虑从这个现有的类派生。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddAuthorizeInteractionResponseGenerator<T>(this IIdentityServerBuilder builder)
            where T : class, IAuthorizeInteractionResponseGenerator
        {
            builder.Services.AddTransient<IAuthorizeInteractionResponseGenerator, T>();

            return builder;
        }

        /// <summary>
        /// Adds the custom authorize request validator.
        /// 添加ICustomAuthorizeRequestValidator实现，以在授权端点定制请求参数验证。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddCustomAuthorizeRequestValidator<T>(this IIdentityServerBuilder builder)
           where T : class, ICustomAuthorizeRequestValidator
        {
            builder.Services.AddTransient<ICustomAuthorizeRequestValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds the custom authorize request validator.
        /// 添加ICustomTokenRequestValidator实现来定制令牌端点处的请求参数验证。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddCustomTokenRequestValidator<T>(this IIdentityServerBuilder builder)
           where T : class, ICustomTokenRequestValidator
        {
            builder.Services.AddTransient<ICustomTokenRequestValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds support for client authentication using JWT bearer assertions.
        /// 使用JWT对客户机认证的支持。
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddJwtBearerClientAuthentication(this IIdentityServerBuilder builder)
        {
            builder.Services.TryAddTransient<IReplayCache, DefaultReplayCache>();
            builder.AddSecretParser<JwtBearerClientAssertionSecretParser>();
            builder.AddSecretValidator<PrivateKeyJwtSecretValidator>();

            return builder;
        }

        /// <summary>
        /// Adds a client configuration validator.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddClientConfigurationValidator<T>(this IIdentityServerBuilder builder)
            where T : class, IClientConfigurationValidator
        {
            builder.Services.AddTransient<IClientConfigurationValidator, T>();

            return builder;
        }

        /// <summary>
        /// Adds the X509 secret validators for mutual TLS.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddMutualTlsSecretValidators(this IIdentityServerBuilder builder)
        {
            builder.AddSecretParser<MutualTlsSecretParser>();
            builder.AddSecretValidator<X509ThumbprintSecretValidator>();
            builder.AddSecretValidator<X509NameSecretValidator>();

            return builder;
        }

        /// <summary>
        /// Adds a custom back-channel logout service.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddBackChannelLogoutService<T>(this IIdentityServerBuilder builder)
            where T : class, IBackChannelLogoutService
        {
            builder.Services.AddTransient<IBackChannelLogoutService, T>();

            return builder;
        }

        // todo: check with later previews of ASP.NET Core if this is still required
        /// <summary>
        /// Adds configuration for the HttpClient used for back-channel logout notifications.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureClient">The configruation callback.</param>
        /// <returns></returns>
        public static IHttpClientBuilder AddBackChannelLogoutHttpClient(this IIdentityServerBuilder builder, Action<HttpClient> configureClient = null)
        {
            const string name = IdentityServerConstants.HttpClients.BackChannelLogoutHttpClient;
            IHttpClientBuilder httpBuilder;

            if (configureClient != null)
            {
                httpBuilder = builder.Services.AddHttpClient(name, configureClient);
            }
            else
            {
                httpBuilder = builder.Services.AddHttpClient(name)
                    .ConfigureHttpClient(client => {
                        client.Timeout = TimeSpan.FromSeconds(IdentityServerConstants.HttpClients.DefaultTimeoutSeconds);
                    });
            }

            builder.Services.AddTransient<IBackChannelLogoutHttpClient>(s =>
            {
                var httpClientFactory = s.GetRequiredService<IHttpClientFactory>();
                var httpClient = httpClientFactory.CreateClient(name);
                var loggerFactory = s.GetRequiredService<ILoggerFactory>();
                
                return new DefaultBackChannelLogoutHttpClient(httpClient, loggerFactory);
            });

            return httpBuilder;
        }


        // todo: check with later previews of ASP.NET Core if this is still required
        /// <summary>
        /// Adds configuration for the HttpClient used for JWT request_uri requests.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureClient">The configruation callback.</param>
        /// <returns></returns>
        public static IHttpClientBuilder AddJwtRequestUriHttpClient(this IIdentityServerBuilder builder, Action<HttpClient> configureClient = null)
        {
            const string name = IdentityServerConstants.HttpClients.JwtRequestUriHttpClient;
            IHttpClientBuilder httpBuilder;

            if (configureClient != null)
            {
                httpBuilder = builder.Services.AddHttpClient(name, configureClient);
            }
            else
            {
                httpBuilder = builder.Services.AddHttpClient(name)
                    .ConfigureHttpClient(client => {
                        client.Timeout = TimeSpan.FromSeconds(IdentityServerConstants.HttpClients.DefaultTimeoutSeconds);
                    });
            }
            
            builder.Services.AddTransient<IJwtRequestUriHttpClient, DefaultJwtRequestUriHttpClient>(s =>
            {
                var httpClientFactory = s.GetRequiredService<IHttpClientFactory>();
                var httpClient = httpClientFactory.CreateClient(name);
                var loggerFactory = s.GetRequiredService<ILoggerFactory>();
                var options = s.GetRequiredService<IdentityServerOptions>();

                return new DefaultJwtRequestUriHttpClient(httpClient, options, loggerFactory);
            });

            return httpBuilder;
        }

        /// <summary>
        /// Adds a custom authorization request parameter store.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddAuthorizationParametersMessageStore<T>(this IIdentityServerBuilder builder)
            where T : class, IAuthorizationParametersMessageStore
        {
            builder.Services.AddTransient<IAuthorizationParametersMessageStore, T>();

            return builder;
        }

        /// <summary>
        /// Adds a custom user session.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddUserSession<T>(this IIdentityServerBuilder builder)
            where T : class, IUserSession
        {
            // This is added as scoped due to the note regarding the AuthenticateAsync
            // method in the IdentityServer4.Services.DefaultUserSession implementation.
            builder.Services.AddScoped<IUserSession, T>();

            return builder;
        }
    }
}