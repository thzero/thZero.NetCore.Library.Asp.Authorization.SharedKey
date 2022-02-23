/* ------------------------------------------------------------------------- *
thZero.NetCore.Library.Asp.Authorization.SharedKey
Copyright (C) 2016-2022 thZero.com

<development [at] thzero [dot] com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 * ------------------------------------------------------------------------- */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace thZero.AspNetCore.SharedKey
{
    public class SharedKeyAuthenticationStartupExtension : AuthStartupExtension<SharedKeyAuthorizationConfiguration>
    {
        #region Public Methods
        public override void ConfigureServicesInitializeAuthentication(IServiceCollection services, IWebHostEnvironment env, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = SharedKeyAuthenticationOptions.AuthenticationScheme;
            })
            .AddSharedKey(services);
        }

        public override void ConfigureServicesInitializeAuthorization(IServiceCollection services, IWebHostEnvironment env, IConfiguration configuration)
        {
            services.AddAuthorization(
                options =>
                {
                    AuthorizationOptions(options);
                    AuthorizationOptionsDefaultPolicy(options);
                });
        }
        #endregion

        #region Protected Methods
        protected virtual void AuthorizationOptions(AuthorizationOptions options)
        {
            options.AddPolicy(AdminApiKeyAuthorizeAttribute.KeyPolicy,
                builder =>
                {
                    builder.AuthenticationSchemes.Add(SharedKeyAuthenticationOptions.AuthenticationScheme);
                    builder.RequireClaim(AdminApiKeyAuthorizeAttribute.KeyPolicy);
                });
            options.AddPolicy(ApiKeyAuthorizeAttribute.KeyPolicy,
                builder =>
                {
                    builder.AuthenticationSchemes.Add(SharedKeyAuthenticationOptions.AuthenticationScheme);
                    builder.RequireClaim(ApiKeyAuthorizeAttribute.KeyPolicy);
                });
        }

        protected virtual void AuthorizationOptionsDefaultPolicy(AuthorizationOptions options)
        {
            options.DefaultPolicy = options.GetPolicy(AdminApiKeyAuthorizeAttribute.KeyPolicy);
        }
        #endregion

        #region Protected Properties
        protected override string ConfigurationSectionKey => "SharedKey";
        #endregion
    }

    public class SharedKeyAuthenticationHandler : AuthenticationHandler<SharedKeyAuthenticationOptions>
    {
        public SharedKeyAuthenticationHandler(IOptionsMonitor<SharedKeyAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IOptions<SharedKeyAuthorizationConfiguration> config)
            : base(options, logger, encoder, clock)
        {
            _config = config.Value;
        }

        #region Protected Methods
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            const string Declaration = "HandleAuthenticateAsync";

            try
            {
                var sharedKey = CheckParameterAuthorizationSharedKey();
                Logger.LogDebug(Logger.LogFormat(Declaration, "authHeader", () => { return sharedKey; }));
                if (string.IsNullOrEmpty(sharedKey))
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed."));
                    return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, SharedKeyAuthenticationOptions.AuthenticationScheme)
                };
                if (_config.Key.Equals(sharedKey))
                    claims.Add(new Claim(ApiKeyAuthorizeAttribute.KeyPolicy, sharedKey));
                if (_config.KeyAdmin.Equals(sharedKey))
                {
                    claims.Add(new Claim(ApiKeyAuthorizeAttribute.KeyPolicy, sharedKey));
                    claims.Add(new Claim(AdminApiKeyAuthorizeAttribute.KeyPolicy, sharedKey));
                }

                if (claims.Count == 0)
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, no claims."));
                    return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                }

                var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SharedKeyAuthenticationOptions.AuthenticationScheme));
                var ticket = new AuthenticationTicket(principal, SharedKeyAuthenticationOptions.AuthenticationScheme);

                Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Success."));
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            catch (Exception ex)
            {
                Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed.", ex));
                return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
            }
        }
        #endregion

        #region Private Methods
        private string CheckParameterAuthorizationSharedKey()
        {
            string result = null;
            if (Request.Headers.ContainsKey(KeyAuthorizationShardKey))
                result = Request.Headers[KeyAuthorizationShardKey];
            else if (Request.Headers.ContainsKey(KeyAuthorizationShardKey2))
                result = Request.Headers[KeyAuthorizationShardKey2];

            return result;
        }
        #endregion

        #region Fields
        private readonly SharedKeyAuthorizationConfiguration _config;
        #endregion

        #region Constants
        private const string KeyAuthorizationShardKey = "x-api-key";
        private const string KeyAuthorizationShardKey2 = "x-auth-key";
        #endregion
    }

    public class SharedKeyAuthenticationOptions : AuthenticationSchemeOptions
    {
        #region Public Methods
        public override void Validate()
        {
            Console.WriteLine("");
        }
        #endregion

        #region Constants
        public const string AuthenticationScheme = "SharedKey";
        #endregion
    }

    public static class SharedKeyAuthenticationHandlerExtensions
    {
        #region Public Methods
        public static AuthenticationBuilder AddSharedKey(this AuthenticationBuilder builder, IServiceCollection services)
        {
            return builder.AddScheme<SharedKeyAuthenticationOptions, SharedKeyAuthenticationHandler>(
                SharedKeyAuthenticationOptions.AuthenticationScheme, // Name of scheme
                SharedKeyAuthenticationOptions.AuthenticationScheme, // Display name of scheme
                options =>
                {
                    //var provider = services.BuildServiceProvider();
                    // Logger, ServiceUserRepository and SharedKeyAuthenticationProcess are all things that were injected into the custom authentication
                    // middleware in ASP.NET Core 1.1. This is now added to the options object instead.
                    //options.Logger = provider.GetService<global::Serilog.ILogger>();
                    //options.ServiceUserRepository = provider.GetService<IServiceUserRepository>();
                    //options.SharedKeyAuthenticationProcess = provider.GetService<ISharedKeyAuthenticationProcess>();
                });
        }
        #endregion
    }

    public class SharedKeyAuthorizationConfiguration : AuthorizationConfiguration
    {
        #region Public Properties
        public string Key { get; set; }
        public string KeyAdmin { get; set; }
        #endregion
    }
}
