namespace ClaimsCookie
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.IdentityModel.Services;
    using System.IdentityModel.Services.Tokens;
    using System.Linq;
    using System.Security.Claims;

    public class ClaimsCookieModule : SessionAuthenticationModule
    {
        public EventHandler<BeforeCreateCookieEventArgs> BeforeCreateCookie;

        public static ClaimsCookieModule Instance
        {
            get
            {
                return FederatedAuthentication.SessionAuthenticationModule as ClaimsCookieModule;
            }
        }

        protected override void InitializePropertiesFromConfiguration()
        {
            this.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.AddOrReplace(new MachineKeySessionSecurityTokenHandler());
        }

        public virtual void CreateSessionSecurityToken(IEnumerable<KeyValuePair<string, object>> user, string extraData = null, string domain = null, string path = null, bool requireSsl = false, bool httpOnly = true, string cookieName = null, bool persistent = false, TimeSpan? persistentCookieLifetime = null)
        {
            if (!string.IsNullOrEmpty(domain)) 
            {
                this.CookieHandler.Domain = domain;
            }

            if (!string.IsNullOrEmpty(path))
            {
                this.CookieHandler.Path = path;
            }

            if (!string.IsNullOrEmpty(cookieName))
            {
                this.CookieHandler.Name = cookieName;
            }

            this.CookieHandler.RequireSsl = requireSsl;
            this.CookieHandler.HideFromClientScript = httpOnly;

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.First(a => a.Key == "name").ToString())
            };

            foreach (var attribute in user)
            {
                var claimType = attribute.Key;

                if (attribute.Value.GetType().IsArray)
                {
                    // Attribute contains an array of values (e.g.: "group" => [ "sales", "producers" ])
                    foreach (var subattribute in attribute.Value as IEnumerable)
                    {
                        claims.Add(new Claim(claimType, subattribute.ToString()));
                    }
                }
                else
                {
                    claims.Add(
                        new Claim(claimType, attribute.Value != null ? attribute.Value.ToString() : string.Empty));
                }
            }

            var principal = new ClaimsPrincipal(new ClaimsIdentity[] { new ClaimsIdentity(claims) });

            this.OnBeforeCreateCookie(new BeforeCreateCookieEventArgs { Principal = principal });

            var session = this.CreateSessionSecurityToken(principal, extraData, DateTime.Now, persistent && persistentCookieLifetime.HasValue ? DateTime.Now.Add(persistentCookieLifetime.Value) : DateTime.MaxValue, false);
            this.AuthenticateSessionSecurityToken(session, true);
        }

        protected virtual void OnBeforeCreateCookie(BeforeCreateCookieEventArgs e)
        {
            if (this.BeforeCreateCookie != null)
                this.BeforeCreateCookie(this, e);
        }
    }
}
