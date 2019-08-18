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
    public class CustomAuthorizeAttribute_V2 : AuthorizeAttribute
    {
        private const string BasicAuthResponseHeader = "WWW-Authenticate";
        private const string BasicAuthResponseHeaderValue = "Basic";
       // private string api_key = "sagloyalty";
        //private string api_pwd = "9x8a184p14z57t7";
       
        public string UsersConfigKey { get; set; }
        public string RolesConfigKey { get; set; }

        private loyalityEntities m_db = new loyalityEntities();


       
        


        public override void OnAuthorization(HttpActionContext actionContext)
        {
            try
            {
                string vendor_api_key = "";
                string vendor_api_pwd = "";
                string merchantUser_api_key = "";
                string merchantUser_api_pwd = "";
               
                
                
                AuthenticationHeaderValue authValue = actionContext.Request.Headers.Authorization;
               

                if (authValue != null && !String.IsNullOrWhiteSpace(authValue.Parameter) && authValue.Scheme == BasicAuthResponseHeaderValue)
                {
                    Credentials_V2 parsedCredentials = ParseAuthorizationHeader(authValue.Parameter);

                    if(parsedCredentials != null)
                    {
                        int typeId = 0;

                        api_Authorization(parsedCredentials.Username, parsedCredentials.Password, out vendor_api_key, out vendor_api_pwd, out merchantUser_api_key, out merchantUser_api_pwd, out typeId);
                        switch (typeId)
                        {
                            case 1:
                                if (!(parsedCredentials.Username == vendor_api_key && parsedCredentials.Password == vendor_api_pwd))
                                {
                                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                                    actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                                    actionContext.Response.ReasonPhrase = "Username & Password not valid";
                                    return;

                                }
                                break;
                            case 2:
                                if (merchantUser_api_key != "Invalid Api Key" && merchantUser_api_pwd != "Invalid Api Pwd")
                                {
                                    if (!(parsedCredentials.Username == merchantUser_api_key && parsedCredentials.Password == merchantUser_api_pwd))
                                    {
                                        actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                                        actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                                        actionContext.Response.ReasonPhrase = "Username & Password not valid";
                                        return;
                                        // is_return = true;
                                    }

                                }
                                break;
                            case 3:
                                if (merchantUser_api_key != "Shop-a-Gain_153868161004000000")
                                {
                                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                                    actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                                    actionContext.Response.ReasonPhrase = "Username & Password not valid";
                                    return;
                                }

                                break;
                            default:
                                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                                actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                                actionContext.Response.ReasonPhrase = "Invalid inputs provided";
                                return;
                                //break;
                        }   //end switch case                   
                   
                    
                    
                    }
                    else
                    {
                         actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                         actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                         actionContext.Response.ReasonPhrase = "Invalid inputs provided";
                        return;
                    }
                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                    actionContext.Response.Headers.Add(BasicAuthResponseHeader, BasicAuthResponseHeaderValue);
                    actionContext.Response.ReasonPhrase = "Please provide valid inputs";
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

        private Credentials_V2 ParseAuthorizationHeader(string authHeader)
        {
            string[] credentials = Encoding.ASCII.GetString(Convert.FromBase64String(authHeader)).Split(new[] { ':' });

            if (credentials.Length != 2 || string.IsNullOrEmpty(credentials[0]) || string.IsNullOrEmpty(credentials[1]))
                return null;

            return new Credentials_V2() { Username = credentials[0], Password = credentials[1], };
        }

      

        public void api_Authorization(string apiKey, string apiPwd,out string vendor_use_api_key, out string vendor_use_api_pwd, out string merchant_api_key, out string merchant_api_pwd, out int typeId)
        {
           
            vendor_use_api_key = "";
            vendor_use_api_pwd = "";
            merchant_api_key = "";
            merchant_api_pwd = "";
            int merchant_id = 0;
            typeId = 0;


            var confirm_api_key = m_db.api_authentication_details.Where(a => a.api_key == apiKey).FirstOrDefault();            
            if(confirm_api_key !=null)
            {
                if (confirm_api_key.api_key == "Shop-a-Gain_153868161004000000")
                {
                    typeId = 3;
                    merchant_api_key ="Shop-a-Gain_153868161004000000"; 
                }
                else
                {
                    var authentication_details = (from obj_api_authentication_details in m_db.api_authentication_details.Where(a => a.api_key == apiKey.Trim())
                                                  join obj_vendor_details in m_db.merchants on obj_api_authentication_details.vendor_id
                                                  equals obj_vendor_details.id
                                                  select new
                                                  {
                                                      obj_api_authentication_details = obj_api_authentication_details,
                                                      obj_vendor_details = obj_vendor_details
                                                  }).FirstOrDefault();

                    if(authentication_details != null)
                    {
                        vendor_use_api_pwd = authentication_details.obj_vendor_details.Password;
                        merchant_id = authentication_details.obj_vendor_details.id;
                        typeId = 1;
                    }

                    var UserDetails = (from ob_merchant_user in m_db.merchant_users
                                       join ob_vendor_details in m_db.merchants
                                       on ob_merchant_user.merchant_id equals ob_vendor_details.id
                                       where (ob_merchant_user.password == apiPwd && ob_vendor_details.id == merchant_id)
                                       select new
                                       {
                                           ob_vendor_details = ob_vendor_details,
                                           ob_merchant_user = ob_merchant_user
                                       }).FirstOrDefault();

                    if (UserDetails != null)
                    {
                        merchant_api_key = apiKey;
                        merchant_api_pwd = UserDetails.ob_merchant_user.password;
                        typeId = 2;
                    }
                    else
                    {
                        merchant_api_key = "Invalid Api Key";
                        merchant_api_pwd = "Invalid Api Pwd";
                    }
                }
            }

           

         


       }
    }
    //Client credential
    public class Credentials_V2
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }


}