namespace ClaimsCookie
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.IdentityModel.Services;
    using System.IdentityModel.Services.Tokens;
    using System.Linq;
    using System.Security.Claims;

    /// <summary>
    /// A custom implementation of a SessionAuthenticationModule that uses a
    /// MachineKeySessionSecurityTokenHandler (to allow web farm scenarios),
    /// and simplifies the creation of a session cookie.
    /// </summary>
    public class ClaimsCookieModule : SessionAuthenticationModule
    {
        /// <summary>
        /// Occurs before the session cookie is created.
        /// </summary>
        public EventHandler<BeforeCreateCookieEventArgs> BeforeCreateCookie;

        /// <summary>
        /// Gets the ClaimsCookieModule used by the web application.
        /// </summary>
        public static ClaimsCookieModule Instance
        {
            get
            {
                return FederatedAuthentication.SessionAuthenticationModule as ClaimsCookieModule;
            }
        }

        /// <summary>
        /// Overrides the default SecurityTokenHandler with a MachineKeySessionSecurityTokenHandler.
        /// </summary>
        protected override void InitializePropertiesFromConfiguration()
        {
            if (this.FederationConfiguration != null)
            {
                this.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.AddOrReplace(new MachineKeySessionSecurityTokenHandler());
            }
        }

        /// <summary>
        /// Creates a ClaimsPrincipal from the specified user data, sets the current HTTP context and thread principal
        /// and writes a session cookie from the resulting SessionSecurityToken using the specified parameters.
        /// </summary>
        /// <param name="user">The user data that will be used to create the claims for the ClaimsPrincipal. 
        /// Array values are converted to multiple claims with the same key.</param>
        /// <param name="extraData">An application defined context string.</param>
        /// <param name="domain">The domain used for the session cookie.</param>
        /// <param name="path">The virtual path used for the session cookie.</param>
        /// <param name="requireSsl">Indicates if the session cookie should only be used with SSL.</param>
        /// <param name="httpOnly">Indicates whether the session cookie should be hidden from client script.</param>
        /// <param name="cookieName">Indicates the name of the session cookie.</param>
        /// <param name="sessionCookieLifetime">The lifetime for the sesion cookie. A null value indicates no expiration.</param>
        /// <param name="persistent">Indicates if the user agent should persist the session cookie. </param>
        [Obsolete("This method is deprecated in favor of CreateSessionCookie() which should be used instead, with the same parameters.")]
        public virtual void CreateSessionSecurityToken(
            IEnumerable<KeyValuePair<string, object>> user,
            string extraData = null,
            string domain = null,
            string path = null,
            bool requireSsl = false,
            bool httpOnly = true,
            string cookieName = null,
            TimeSpan? sessionCookieLifetime = null,
            bool persistent = false)
        {
            this.CreateSessionCookie(user, extraData, domain, path, requireSsl, httpOnly, cookieName, sessionCookieLifetime, persistent);
        }

        /// <summary>
        /// Creates a ClaimsPrincipal from the specified user data, sets the current HTTP context and thread principal
        /// and writes a session cookie from the resulting SessionSecurityToken using the specified parameters.
        /// </summary>
        /// <param name="user">The user data that will be used to create the claims for the ClaimsPrincipal. 
        /// Array values are converted to multiple claims with the same key.</param>
        /// <param name="context">An application defined context string.</param>
        /// <param name="domain">The domain used for the session cookie.</param>
        /// <param name="path">The virtual path used for the session cookie.</param>
        /// <param name="requireSsl">Indicates if the session cookie should only be used with SSL.</param>
        /// <param name="httpOnly">Indicates whether the session cookie should be hidden from client script.</param>
        /// <param name="cookieName">Indicates the name of the session cookie.</param>
        /// <param name="sessionCookieLifetime">The lifetime for the sesion cookie. A null value indicates no expiration.</param>
        /// <param name="persistent">Indicates if the user agent should persist the session cookie. </param>
        public virtual void CreateSessionCookie(
            IEnumerable<KeyValuePair<string, object>> user,
            string context = null,
            string domain = null,
            string path = null,
            bool requireSsl = false,
            bool httpOnly = true,
            string cookieName = null,
            TimeSpan? sessionCookieLifetime = null,
            bool persistent = false)
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
                                 new Claim(ClaimTypes.Name, user.First(a => a.Key == "name").Value.ToString()),
                                 new Claim(
                                     ClaimTypes.NameIdentifier,
                                     user.First(a => a.Key == "user_id").Value.ToString()),
                                 new Claim(
                                     "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider",
                                     user.First(a => a.Key == "connection").Value.ToString())
                             };

            foreach (var attribute in user)
            {
                var claimType = attribute.Key;

                if (attribute.Value != null && attribute.Value.GetType().IsArray)
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

            var principal = new ClaimsPrincipal(new ClaimsIdentity[] { new ClaimsIdentity(claims, "Auth0") });
            this.OnBeforeCreateCookie(new BeforeCreateCookieEventArgs { Principal = principal });

            var session = this.CreateSessionSecurityToken(
                principal,
                context,
                DateTime.UtcNow,
                sessionCookieLifetime.HasValue
                    ? DateTime.UtcNow.Add(sessionCookieLifetime.Value)
                    : DateTime.MaxValue.ToUniversalTime(),
                persistent);
            this.AuthenticateSessionSecurityToken(session, true);
        }

        protected virtual void OnBeforeCreateCookie(BeforeCreateCookieEventArgs e)
        {
            if (this.BeforeCreateCookie != null)
                this.BeforeCreateCookie(this, e);
        }
    }
}
