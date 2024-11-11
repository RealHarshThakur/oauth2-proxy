---
id: civo
title: Civo
---

1. Create a new OAuth application
    * Request Civo team to create a new OAuth application.
    * You can fill in the name, homepage, and description however you wish.
    * In the "Application callback URL" field, enter: `https://oauth-proxy/oauth2/callback`, substituting `oauth2-proxy` 
      with the actual hostname that oauth2-proxy is running on. The URL must match oauth2-proxy's configured redirect URL.
2. Note the Client ID and Client Secret.

To use the provider, pass the following options:

```
   --provider=civo
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```


3. Restrict based on account_id
* Using a flag `civo-account`(account_id) you can restrict access to a specific account.

An example config can be found at `contrib/local-environment/oauth2-proxy-civo.cfg`.
Alternatively, set the equivalent options in the config file. The redirect URL defaults to 
`https://<requested host header>/oauth2/callback`. If you need to change it, you can use the `--redirect-url` command-line option.

4. Restrict based on civo_permissions
* Using a flag `civo-permissions` (civo_permissions) you can restrict access to a given set of permissions

An example config can be found at `contrib/local-environment/oauth2-proxy-civo.cfg`.
Alternatively, set the equivalent options in the config file. 

* Using a flag `civo-permissions-url` (civo_permissions_url) you can pass the URL to call to get the permissions of a given user in a specified account
