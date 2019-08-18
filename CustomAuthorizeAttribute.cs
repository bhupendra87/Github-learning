using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;
using System.Net;
using System.Configuration;
using System.Web.Http.Controllers;
using System.Net.Http.Headers;
using System.Web.Http;
using System.Net.Http;
using Loyality.Models;

namespace Loyality.Controllers
{

    //custom authorize filter attribute
    public class CustomAuthorizeAttribute : AuthorizeAttribute
    {
        private const string BasicAuthResponseHeader = "WWW-Authenticate";
        private const string BasicAuthResponseHeaderValue = "Basic";
        private string api_key = "sagloyalty";
        private string api_pwd = "9x8a184p14z57t7";
       
        public string UsersConfigKey { get; set; }
        public string RolesConfigKey { get; set; }

        private loyalityEntities m_db = new loyalityEntities();


       
        


        public override void OnAuthorization(HttpActionContext actionContext)
        {
            try
            {
                
                
                AuthenticationHeaderValue authValue = actionContext.Request.Headers.Authorization;

                if (authValue != null && !String.IsNullOrWhiteSpace(authValue.Parameter) && authValue.Scheme == BasicAuthResponseHeaderValue)
                {
                    Credentials parsedCredentials = ParseAuthorizationHeader(authValue.Parameter);

                    if (parsedCredentials != null)
                    {


                        if(!(parsedCredentials.Username == api_key && parsedCredentials.Password == api_pwd))
                        {
                            actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                            actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                            actionContext.Response.ReasonPhrase = "Username & Password not valid";
                            return;
                        }
                    }
                    else
                    {
                        /* actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                         actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                         actionContext.Response.ReasonPhrase = "Invalid inputs provided";*/
                        return;
                    }
                }
                else
                {
                    /*actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                    actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                    actionContext.Response.ReasonPhrase = "Please provide valid inputs";*/
                    return;
                }
            }
            catch (Exception)
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                actionContext.Response.ReasonPhrase = "Please provide valid inputs";
                return;

            }
        }

        private Credentials ParseAuthorizationHeader(string authHeader)
        {
            string[] credentials = Encoding.ASCII.GetString(Convert.FromBase64String(authHeader)).Split(new[] { ':' });

            if (credentials.Length != 2 || string.IsNullOrEmpty(credentials[0]) || string.IsNullOrEmpty(credentials[1]))
                return null;

            return new Credentials() { Username = credentials[0], Password = credentials[1], };
        }

       /* public void api_authentication(out string use_api_key, out string use_api_pwd)
        {
            use_api_key = "";
            use_api_pwd = "";

            var authentication_details = m_db.api_authentication_details.FirstOrDefault();
            if (authentication_details != null)
            {
                use_api_key = authentication_details.api_key;
               // use_api_pwd = authentication_details.api_pwd;
            }
        }*/
    }
    //Client credential
    public class Credentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }


}