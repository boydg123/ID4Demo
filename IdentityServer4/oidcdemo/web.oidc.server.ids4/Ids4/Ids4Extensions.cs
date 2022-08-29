using IdentityServer4;
using IdentityServer4.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace ServerSite.Ids4
{
    public static class Ids4Extensions
    {
        public static IServiceCollection AddIds4(this IServiceCollection @this)
        {
            @this
                .AddAuthentication();

            @this
                .AddIdentityServer(SetIdentityServerOptions)
                .AddDeveloperSigningCredential(persistKey: true)
                .AddInMemoryApiScopes(Resources.AllApiScopes)
                .AddInMemoryIdentityResources(Resources.AllIdentityResources)
                .AddInMemoryApiResources(Resources.AllApiResources)
                .AddInMemoryClients(Clients.All)
                .AddTestUsers(Users.All);

            return @this;
        }

        public static IApplicationBuilder UseIds4(this IApplicationBuilder @this)
        {
            return @this.UseIdentityServer();
        }

        private static void SetIdentityServerOptions(IdentityServerOptions options)
        {
            options.IssuerUri = "http://localhost:8010";
            options.UserInteraction = new UserInteractionOptions
            {
                LoginUrl = "/account/login",
                LoginReturnUrlParameter = "resumeUrl",
                LogoutUrl = "/account/logout",
                LogoutIdParameter = "logoutId",
                ErrorUrl = "/ids4/error",
                ErrorIdParameter = "errorId"
            };
        }
    }
}
