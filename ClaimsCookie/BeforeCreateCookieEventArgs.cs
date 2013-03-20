namespace ClaimsCookie
{
    using Microsoft.IdentityModel.Claims;
    using System;

    public class BeforeCreateCookieEventArgs : EventArgs
    {
        public ClaimsPrincipal Principal { get; set; }
    }
}
