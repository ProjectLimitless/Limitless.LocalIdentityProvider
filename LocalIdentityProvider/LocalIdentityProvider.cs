/** 
* This file is part of Project Limitless.
* Copyright © 2016 Donovan Solms.
* Project Limitless
* https://www.projectlimitless.io
* 
* Project Limitless is free software: you can redistribute it and/or modify
* it under the terms of the Apache License Version 2.0.
* 
* You should have received a copy of the Apache License Version 2.0 with
* Project Limitless. If not, see http://www.apache.org/licenses/LICENSE-2.0.
*/

using System;
using System.Reflection;
using System.Collections.Generic;

using Limitless.Runtime.Types;
using Limitless.Runtime.Interfaces;
using Limitless.LocalIdentityProvider.Models;

namespace Limitless.LocalIdentityProvider
{
    /// <summary>
    /// Provides identity for local-only users.
    /// </summary>
    public class LocalIdentityProvider : IModule, IIdentityProvider
    {
        /// <summary>
        /// The logger.
        /// </summary>
        private readonly ILogger _log;
        /// <summary>
        /// The database provider.
        /// </summary>
        private readonly IDatabaseProvider _db;
        /// <summary>
        /// JWT secret key.
        /// </summary>
        private readonly byte[] _key;
        /// <summary>
        /// The local configuration.
        /// </summary>
        private LocalIdentityConfig _config;

        /// <summary>
        /// Creates a new instance of the identity provider using 
        /// the supplied <see cref="ILogger"/>.
        /// </summary>
        /// <param name="log">The <see cref="ILogger"/> to use</param>
        /// <param name="db">The <see cref="IDatabaseProvider"/> to use</param>
        public LocalIdentityProvider(ILogger log, IDatabaseProvider db)
        {
            _log = log;
            _db = db;
            // TODO: Key needs to be from config
            _key = new byte[] { 112, 163, 236, 130, 140, 212, 109, 228, 219, 63, 15, 4, 136, 43, 239, 186 };
            _log.Debug("Created with log type '{0}'", _log.GetType());
            _log.Debug("Created with Database provider type '{0}'", _db.GetType());
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IModule.Configure"/>
        /// </summary>
        public void Configure(dynamic settings)
        {
            if (settings == null)
            {
                throw new NullReferenceException("Settings can not be null");
            }
            var config = (LocalIdentityConfig)settings;
            _config = config;
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IModule.GetConfigurationType"/>
        /// </summary>
        public Type GetConfigurationType()
        {
            return typeof(LocalIdentityConfig);
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IModule.GetTitle"/>
        /// </summary>
        public string GetTitle()
        {
            var assembly = typeof(LocalIdentityProvider).Assembly;
            var attribute = assembly.GetCustomAttribute<AssemblyTitleAttribute>();
            return attribute != null ? attribute.Title : "Unknown";
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IModule.GetAuthor"/>
        /// </summary>
        public string GetAuthor()
        {
            var assembly = typeof(LocalIdentityProvider).Assembly;
            var attribute = assembly.GetCustomAttribute<AssemblyCompanyAttribute>();
            return attribute != null ? attribute.Company : "Unknown";
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IModule.GetVersion"/>
        /// </summary>
        public string GetVersion()
        {
            var assembly = typeof(LocalIdentityProvider).Assembly;
            return assembly.GetName().Version.ToString();
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IModule.GetDescription"/>
        /// </summary>
        public string GetDescription()
        {
            var assembly = typeof(LocalIdentityProvider).Assembly;
            var attribute = assembly.GetCustomAttribute<AssemblyDescriptionAttribute>();
            return attribute != null ? attribute.Description : "Unknown";
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IIdentityProvider.TokenLogin"/>
        /// </summary>
        public LoginResult TokenLogin(string token)
        {
            try
            {
                var payload = Jose.JWT.Decode<LocalIdentityToken>(token, _key);
                var tokenExpires = DateTime.FromBinary(payload.exp);
                if (tokenExpires > DateTime.UtcNow)
                {
                    var userModel = _db.QuerySingle<Users>(
                        @"SELECT * FROM users WHERE id = @0 AND isDeleted = 0", payload.uid
                    );
                    if (userModel != null)
                    {
                        var user = new BaseUser(userModel.Username, true)
                        {
                            Name = userModel.FirstName,
                            Surname = userModel.LastName
                        };
                        return new LoginResult(user);
                    }
                }
                return new LoginResult(false, "Your token has expired");
            }
            catch (Exception)
            {
                // Nothing here
            }
            return new LoginResult(false, "A valid access token is required");
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IIdentityProvider.Login"/>
        /// </summary>
        /// <param name="username">The username to log in with</param>
        /// <param name="password"></param>
        public LoginResult Login(string username, string password)
        {
            var userModel = _db.QuerySingle<Users>(
                @"SELECT * FROM users WHERE username = @0 AND isDeleted = 0", username
            );
            if (userModel == null)
            {
                return new LoginResult(false);
            }
            if (BCrypt.Net.BCrypt.Verify(password, userModel.Password) == false)
            {
                return new LoginResult(false);
            }

            // Generate access token
            var payload = new LocalIdentityToken
            {
                aud = "limitless.local",
                exp = DateTime.Now.AddDays(1).ToBinary(),
                iss = "limitless.local",
                name = $"{userModel.FirstName} {userModel.LastName}",
                sub = "Local User",
                uid = userModel.ID
            };
            // TODO: Change to GCM-based token
            string token = Jose.JWT.Encode(payload, _key, Jose.JwsAlgorithm.HS512);

            var user = new BaseUser(username, true)
            {
                Name = userModel.FirstName,
                Surname = userModel.LastName,
                AccessToken = token
            };
            return new LoginResult(user);
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IIdentityProvider.List"/>
        /// </summary>
        public List<dynamic> List()
        {
            var users = _db.QueryMany<Users>(
                @"SELECT * FROM users WHERE isDeleted = 0"
            );
            if (users == null)
            {
                return new List<dynamic>();
            }
            var output = new List<dynamic>();
            foreach (Users user in users)
            {
                dynamic userData = user;
                userData.Password = "";
                output.Add(userData);
            }
            return output;
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interfaces.IIdentityProvider.View(dynamic)"/>
        /// </summary>
        public APIResponse View(dynamic id)
        {
            var response = new APIResponse();
            var user = _db.QuerySingle<Users>(
                @"SELECT * FROM users WHERE id = @0 AND isDeleted = 0", id
            );
            if (user == null)
            {
                response.StatusCode = 404;
                response.StatusMessage = "The user could not be found";
                return response;
            }
            response.Data = user;
            return response;
        }
    }
}
