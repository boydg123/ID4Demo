using ClientSite.Oidc;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace web.oidc.client.hybrid
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(_ => _.AddConsole());
            services.AddRouting();
            services.AddControllersWithViews();
            services.AddOidcAuthentication();
        }



        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(_ => _.MapDefaultControllerRoute());
        }
    }
}
