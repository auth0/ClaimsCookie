using System;
using Microsoft.Web.Infrastructure.DynamicModuleHelper;

[assembly: WebActivatorEx.PreApplicationStartMethod(typeof($rootnamespace$.App_Start.ClaimsCookieConfig), "PreAppStart")]

namespace $rootnamespace$.App_Start
{
    public static class ClaimsCookieConfig
    {
        public static void PreAppStart()
        {
            DynamicModuleUtility.RegisterModule(typeof(ClaimsCookie.ClaimsCookieModule));
        }
    }
}