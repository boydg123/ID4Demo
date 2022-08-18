using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServerSite.Ids4;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace web.oidc.server.ids4
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(_ => _.AddConsole());

            services.AddRouting();

            services.AddControllersWithViews();

            services.AddIds4();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseDeveloperExceptionPage();

            app.UseIds4();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseEndpoints(_ => _.MapDefaultControllerRoute());
        }
    }
}
