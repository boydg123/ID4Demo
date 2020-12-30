// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Configuration;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Builder extension methods for registering in-memory services
    /// 各种“in-memory“配置API允许从配置对象的内存列表配置IdentityServer。 这些“in-memory”的集合可以在宿主应用程序中进行硬编码，
    /// 也可以从配置文件或数据库动态加载。 但是，在设计时，只有托管应用程序启动时才会创建这些集合。
    /// 使用这些配置API可用于原型设计，开发和/或测试时不需要在运行时动态查询配置数据的数据库。
    /// 如果配置很少改变，这种配置方式也可能适用于生产方案，或者如果必须更改值，则需要重新启动应用程序并不方便。
    /// </summary>
    public static class IdentityServerBuilderExtensionsInMemory
    {
        /// <summary>
        /// Adds the in memory caching.
        /// 要使用下面描述的任何缓存，必须在DI中注册ICache的实现。 此API注册基于ASP.NET Core的ICache 的MemoryCache默认内存缓存实现。
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryCaching(this IIdentityServerBuilder builder)
        {
            builder.Services.TryAddSingleton<IMemoryCache, MemoryCache>();
            builder.Services.TryAddTransient(typeof(ICache<>), typeof(DefaultCache<>));

            return builder;
        }

        /// <summary>
        /// Adds the in memory identity resources.
        /// 添加基于IResourceStore的IdentityResource的内存集合注册实现，以注册身份验证资源。
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="identityResources">The identity resources.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryIdentityResources(this IIdentityServerBuilder builder, IEnumerable<IdentityResource> identityResources)
        {
            builder.Services.AddSingleton(identityResources);
            builder.AddResourceStore<InMemoryResourcesStore>();

            return builder;
        }

        /// <summary>
        /// Adds the in memory identity resources.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="section">The configuration section containing the configuration data.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryIdentityResources(this IIdentityServerBuilder builder, IConfigurationSection section)
        {
            var resources = new List<IdentityResource>();
            section.Bind(resources);

            return builder.AddInMemoryIdentityResources(resources);
        }

        /// <summary>
        /// Adds the in memory API resources.
        /// 添加基于IResourceStore的ApiResource的内存集合注册实现，以注册API资源。
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="apiResources">The API resources.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryApiResources(this IIdentityServerBuilder builder, IEnumerable<ApiResource> apiResources)
        {
            builder.Services.AddSingleton(apiResources);
            builder.AddResourceStore<InMemoryResourcesStore>();

            return builder;
        }

        /// <summary>
        /// Adds the in memory API resources.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="section">The configuration section containing the configuration data.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryApiResources(this IIdentityServerBuilder builder, IConfigurationSection section)
        {
            var resources = new List<ApiResource>();
            section.Bind(resources);

            return builder.AddInMemoryApiResources(resources);
        }

        /// <summary>
        /// Adds the in memory API scopes.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="apiScopes">The API scopes.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryApiScopes(this IIdentityServerBuilder builder, IEnumerable<ApiScope> apiScopes)
        {
            builder.Services.AddSingleton(apiScopes);
            builder.AddResourceStore<InMemoryResourcesStore>();

            return builder;
        }

        /// <summary>
        /// Adds the in memory scopes.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="section">The configuration section containing the configuration data.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryApiScopes(this IIdentityServerBuilder builder, IConfigurationSection section)
        {
            var resources = new List<ApiScope>();
            section.Bind(resources);

            return builder.AddInMemoryApiScopes(resources);
        }

        /// <summary>
        /// Adds the in memory clients.
        /// 添加基于IClientStore和ICorsPolicyService的内存集合注册实现，以注册客户端配置对象。
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="clients">The clients.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryClients(this IIdentityServerBuilder builder, IEnumerable<Client> clients)
        {
            builder.Services.AddSingleton(clients);

            builder.AddClientStore<InMemoryClientStore>();

            var existingCors = builder.Services.Where(x => x.ServiceType == typeof(ICorsPolicyService)).LastOrDefault();
            if (existingCors != null &&
                existingCors.ImplementationType == typeof(DefaultCorsPolicyService) &&
                existingCors.Lifetime == ServiceLifetime.Transient)
            {
                // if our default is registered, then overwrite with the InMemoryCorsPolicyService
                // otherwise don't overwrite with the InMemoryCorsPolicyService, which uses the custom one registered by the host
                builder.Services.AddTransient<ICorsPolicyService, InMemoryCorsPolicyService>();
            }

            return builder;
        }


        /// <summary>
        /// Adds the in memory clients.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="section">The configuration section containing the configuration data.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryClients(this IIdentityServerBuilder builder, IConfigurationSection section)
        {
            var clients = new List<Client>();
            section.Bind(clients);

            return builder.AddInMemoryClients(clients);
        }


        /// <summary>
        /// Adds the in memory stores.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddInMemoryPersistedGrants(this IIdentityServerBuilder builder)
        {
            builder.Services.TryAddSingleton<IPersistedGrantStore, InMemoryPersistedGrantStore>();
            builder.Services.TryAddSingleton<IDeviceFlowStore, InMemoryDeviceFlowStore>();

            return builder;
        }
    }
}