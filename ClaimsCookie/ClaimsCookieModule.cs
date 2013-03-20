namespace ClaimsCookie
{
    using Microsoft.IdentityModel.Claims;
    using Microsoft.IdentityModel.Web;
    using System;
    using System.Collections.Generic;
    using System.Linq;

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

        protected override void InitializePropertiesFromConfiguration(string serviceName)
        {
            this.ServiceConfiguration.SecurityTokenHandlers.AddOrReplace(new MachineKeySessionSecurityTokenHandler());
        }

        public virtual void CreateSessionSecurityToken(IDictionary<string, string> user, string extraData = null, string domain = null, string path = null, bool requireSsl = false, bool httpOnly = true, string cookieName = null, bool persistent = false, TimeSpan? persistentCookieLifetime = null)
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

            user.Add(new KeyValuePair<string, string>(ClaimTypes.Name, user["name"]));
            var claims = from attribute in user
                         select new Claim(attribute.Key, attribute.Value);

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
