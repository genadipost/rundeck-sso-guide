Rundeck SSO guide
=================

This is a step by step guide to configure [single sign-on](https://en.wikipedia.org/wiki/Single_sign-on) for [Rundeck](https://github.com/rundeck/rundeck) in enterprise environment using [Active Directory](https://en.wikipedia.org/wiki/Active_Directory),[SSSD](https://pagure.io/SSSD/sssd/) and [Apache](https://httpd.apache.org/).

- Apache will serve as a reverse proxy that will pass REMOTE_USER header to rundeck
- Authentication will be handled with Kerberos + [mod_auth_gssapi](https://github.com/modauthgssapi/mod_auth_gssapi) (as replacement for ageing mod_auth_krb)
- [mod_auth_gssapi](https://github.com/modauthgssapi/mod_auth_gssapi) will populate the REMOTE_USER header
- [mod_lookup_identity](https://www.adelton.com/apache/mod_lookup_identity) will retrieve additional information about the authenticated user
- Authorization will be handled by [Rundeck acls](http://rundeck.org/docs/administration/access-control-policy.html)

This guide assumes Rundeck is hosted on Centos/RHEL server.

Apache + Kerberos (via GSS-API):
=====
We will use [Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol)) as authentication method (any method supported by [GSS-API](https://en.wikipedia.org/wiki/Generic_Security_Services_Application_Program_Interface) can be used).

**On Rundeck host**:

Install Apache, Kerberos client tools, and gss-api apache module:
```
yum install -y krb5-workstation httpd mod_auth_gssapi
```

To configure Kerberos edit ```/etc/krb5.conf```:
```
includedir /etc/krb5.conf.d/

includedir /var/lib/sss/pubconf/krb5.include.d/
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 rdns = false
 default_realm = TEST.LOCAL
 default_ccache_name = KEYRING:persistent:%{uid}

 TEST.LOCAL = {
  kdc = dc0.test.local
  admin_server = dc0.test.local
 }

[domain_realm]
 test.local = TEST.LOCAL
 .test.local = TEST.LOCAL
```

Change TEST.LOCAL to your domain.

Tests the Kerberos configuration by running kinit/klist with already existing AD user:
```
[root@rundeck ~]# kinit genadipost
Password for genadipost@TEST.LOCAL:
[root@rundeck ~]# klist
Ticket cache: KEYRING:persistent:0:0
Default principal: genadipost@TEST.LOCAL

Valid starting       Expires              Service principal
05/01/2017 01:23:06  05/01/2017 11:23:06  krbtgt/TEST.LOCAL@TEST.LOCAL
        renew until 05/08/2017 01:23:02

--------------------------------------
```

**On Active Directory host**:

Create DNS record:
```
dnscmd %LOGONSERVER% /RecordAdd test.local rundeck A 192.168.227.148
```
Create new user:
```
dsadd user "cn=rundeck,cn=Users,dc=test,dc=local" -upn rundeck -pwd mypassword -pwdneverexpires yes
```

Create SPN for HTTP service SPN:
```
setspn -A HTTP/rundeck.test.local rundeck
```

To validate the successful execution of the above setspn executions, do:
```
setspn -U -l rundeck
```

Create a keytab:
```
ktpass -princ HTTP/rundeck.test.local@TEST.LOCAL -pass mypassword -mapuser rundeck@TEST.LOCAL -pType KRB5_NT_PRINCIPAL -crypto all -out "C:\Users\Administrator\Desktop\http_rundeck.keytab"
```

**Copy the keytab to /etc/httpd/http.keytab on Rundeck host**

**On Rundeck host**:

Configure kerberos authentication in Apache config file (/etc/httpd/conf/httpd.conf):
```
<VirtualHost *:80>
   serverName rundeck.test.local

   <Location />
    AuthType GSSAPI
    AuthName "Kerberos Login"
    GssapiCredStore keytab:/etc/httpd/http.keytab
    Require valid-user
   </Location>
</VirtualHost>
```

restart Apache service:
```
systemctl restart httpd
```

Test the authentication configuration.

When there are no vaild users, authentication should fail:
```
[root@rundeck ~]# klist
klist: Credentials cache keyring 'persistent:0:0' not found

[root@rundeck ~]# curl -u : --negotiate http://rundeck.test.local/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
</body></html>
```

Now get a valid ticket by running kinit and retry the curl:
```
[root@rundeck ~]# kinit genadipost
Password for genadipost@TEST.LOCAL:
[root@rundeck ~]# klist
Ticket cache: KEYRING:persistent:0:0
Default principal: genadipost@TEST.LOCAL

Valid starting       Expires              Service principal
05/01/2017 11:19:23  05/01/2017 21:19:23  krbtgt/TEST.LOCAL@TEST.LOCAL
        renew until 05/08/2017 11:19:21
[root@rundeck ~]# curl -u : --negotiate http://rundeck.test.local/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /
on this server.</p>
<p>Additionally, a 401 Unauthorized
error was encountered while trying to use an ErrorDocument to handle the request.</p>
</body></html>
```

The authentication has succeeded, don't worry about the 403 code.

mod_lookup_identity:
=====

- We will supply REMOTE_USER header to be used as username in rundeck, also we need to supply list of roles to which we will write ACL policies.
- We can use any Active Directory user attributes, i will use the ```memberOf``` attribute that contains list of groups the user is included in.
- To query and populate the attribute in a header we will use [mod_lookup_identity](https://www.adelton.com/apache/mod_lookup_identity/) together with sssd.

Install and configure sssd for active directory authentication:

**On Active Directory host**:

Assuming you created DNS for rundeck server lets create a host SPN and two keytabs for sssd.

Create SPN for host service SPN:
```
setspn -A host/rundeck.test.local rundeck
```

Create default and host SPN:
```
ktpass -princ rundeck.test.local@TEST.LOCAL -pass mypassword -mapuser rundeck@TEST.LOCAL -pType KRB5_NT_PRINCIPAL -crypto all -out "C:\Users\Administrator\Desktop\rundeck.keytab"
ktpass -princ host/rundeck.test.local@TEST.LOCAL -pass mypassword -mapuser rundeck@TEST.LOCAL -pType KRB5_NT_PRINCIPAL -crypto all -out "C:\Users\Administrator\Desktop\host_krb5.keytab"
```

**Copy both keytabs to the rundeck hosts.**

To merge both keytab files we will user ktutil:

Copy both keytabs to the rundeck hosts.

**On Rundeck host**:

To merge both keytab files use ktutil:
```
> ktutil

ktutil: read_kt rundeck.keytab
ktutil: read_kt host_rundeck.keytab
write_kt /etc/krb5.keytab
quit
```
Its important that the keytab will have the right name and will be at correct path as sssd expects the keytab to reside in /etc/krb5.keytab.

Check the keytab, the output should contain a row for every principal/encryption:

```
klist -k -t -e /etc/krb5.keytab
Keytab name: FILE:/etc/krb5.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   4 05/02/2017 06:37:16 rundeck.test.local@TEST.LOCAL (des-cbc-crc)
   4 05/02/2017 06:37:16 rundeck.test.local@TEST.LOCAL (des-cbc-md5)
   4 05/02/2017 06:37:16 rundeck.test.local@TEST.LOCAL (arcfour-hmac)
   4 05/02/2017 06:37:16 rundeck.test.local@TEST.LOCAL (aes256-cts-hmac-sha1-96)
   4 05/02/2017 06:37:16 rundeck.test.local@TEST.LOCAL (aes128-cts-hmac-sha1-96)
   5 05/02/2017 06:37:16 host/rundeck.test.local@TEST.LOCAL (des-cbc-crc)
   5 05/02/2017 06:37:16 host/rundeck.test.local@TEST.LOCAL (des-cbc-md5)
   5 05/02/2017 06:37:16 host/rundeck.test.local@TEST.LOCAL (arcfour-hmac)
   5 05/02/2017 06:37:16 host/rundeck.test.local@TEST.LOCAL (aes256-cts-hmac-sha1-96)
   5 05/02/2017 06:37:16 host/rundeck.test.local@TEST.LOCAL (aes128-cts-hmac-sha1-96)
```

Install sssd and active directory provider:
```
yum install  sssd sssd-ad
```

Configure /etc/sssd/sssd.conf:
```
[sssd]
domains = test.local
config_file_version = 2
services = nss, pam, pac

[domain/test.local]
ad_domain = test.local
krb5_realm = TEST.LOCAL
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = True
fallback_homedir = /home/%u@%d
access_provider = ad
```

Change permissions:
```
chmod 600 /etc/sssd/sssd.conf
```

Restart sssd service, if restart is successful it will confirm sssd is able to read the configuration file and keytab.
```
systemctl restart sssd
```

mod_lookup_identity retrieves user attributes from SSSD (via D-Bus).

Install -y mod_lookup_identity and sssd-dbus:
```
yum install mod_lookup_identity sssd-dbus
```

Edit /etc/sssd/sssd.conf; enable the SSSD ifp InfoPipe responder, permit the apache user to query it, and configure the attributes that you want to expose.
Add the following configuration to sssd.conf:
```
[sssd]
domains = test.local
config_file_version = 2
services = nss, pam, pac, ifp

[domain/test.local]
ad_domain = test.local
krb5_realm = TEST.LOCAL
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = True
fallback_homedir = /home/%u@%d
access_provider = ad

[ifp]
allowed_uids = apache, root
```

Restart SSSD:
```
systemctl restart sssd
```

You can test the SSSD InfoPipe directly via the dbus-send utility:
```
[root@rundeck ~]# dbus-send --print-reply --system     --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe     org.freedesktop.sssd.infopipe.GetUserAttr string:genadipost@test.local array:string:name
method return sender=:1.543 -> dest=:1.557 reply_serial=2
   array [
      dict entry(
         string "name"
         variant             array [
               string "genadipost@test.local"
            ]
      )
   ]

```

Now update the Apache configuration to populate the request environment. 
```LookupUserGroups REMOTE_USER_GROUP :``` will perform lookup user groups multi-valued result will be separated with ```:```.
 Do not forget the LoadModule directive.

```
LoadModule lookup_identity_module modules/mod_lookup_identity.so

<VirtualHost *:80>
  ServerName rundeck.test.local

  <Location />
    AuthType GSSAPI
    AuthName "Kerberos Login"
    GssapiCredStore keytab:/etc/httpd/app.keytab
    Require valid-user

    LookupUserGroups REMOTE_USER_GROUP :
  </Location>

</VirtualHost>
```

Default SELinux policy prevents Apache from communicating with SSSD over D-Bus. Flip httpd_dbus_sssd to 1:
```
setsebool -P httpd_dbus_sssd 1
```

Restart Apache:
```
systemctl restart httpd
```

The new configuration can be tested by increasing the Apache log level to debug.
Edit /etc/httpd/conf/httpd.conf:
```
#
# LogLevel: Control the number of messages logged to the error_log.
# Possible values include: debug, info, notice, warn, error, crit,
# alert, emerg.
#
LogLevel debug
```

Restart Apache:
```
systemctl restart httpd
```

Get vaild ticket and run curl:
```
[root@rundeck ~]# kinit genadipost
Password for genadipost@TEST.LOCAL:
[root@rundeck ~]# curl -u : --negotiate http://rundeck.test.local/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /
on this server.</p>
<p>Additionally, a 401 Unauthorized
error was encountered while trying to use an ErrorDocument to handle the request.</p>
</body></html>
```

Check the Apache log:
```
[root@rundeck ~]# tail -n30 /var/log/httpd/error_log
[Tue May 02 09:35:25.446927 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of Require valid-user : denied (no authenticated user yet)
[Tue May 02 09:35:25.446946 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of <RequireAny>: denied (no authenticated user yet)
[Tue May 02 09:35:25.451900 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of Require valid-user : granted
[Tue May 02 09:35:25.451923 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of <RequireAny>: granted
[Tue May 02 09:35:25.451963 2017] [auth_gssapi:debug] [pid 33379] mod_auth_gssapi.c(656): [client 192.168.227.148:41672] GSSapiImpersonate not On, skipping impersonation.
[Tue May 02 09:35:25.452048 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of Require valid-user : denied (no authenticated user yet)
[Tue May 02 09:35:25.452058 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of <RequireAny>: denied (no authenticated user yet)
[Tue May 02 09:35:25.452067 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of Require valid-user : granted
[Tue May 02 09:35:25.452072 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of <RequireAny>: granted
[Tue May 02 09:35:25.452088 2017] [auth_gssapi:debug] [pid 33379] mod_auth_gssapi.c(656): [client 192.168.227.148:41672] GSSapiImpersonate not On, skipping impersonation.
[Tue May 02 09:35:25.452098 2017] [:debug] [pid 33379] mod_lookup_identity.c(424): invoked for user genadipost@TEST.LOCAL
[Tue May 02 09:35:25.488617 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-519@test.local
[Tue May 02 09:35:25.488638 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1104@test.local
[Tue May 02 09:35:25.488640 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1112@test.local
[Tue May 02 09:35:25.488642 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-513@test.local
[Tue May 02 09:35:25.488643 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-572@test.local
[Tue May 02 09:35:25.488644 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1111@test.local
[Tue May 02 09:35:25.488646 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1106@test.local
[Tue May 02 09:35:25.488662 2017] [:debug] [pid 33379] mod_lookup_identity.c(424): invoked for user genadipost@TEST.LOCAL
[Tue May 02 09:35:25.489227 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-519@test.local
[Tue May 02 09:35:25.489234 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1104@test.local
[Tue May 02 09:35:25.489236 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1112@test.local
[Tue May 02 09:35:25.489237 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-513@test.local
[Tue May 02 09:35:25.489239 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-572@test.local
[Tue May 02 09:35:25.489240 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1111@test.local
[Tue May 02 09:35:25.489241 2017] [:info] [pid 33379] dbus call GetUserGroups returned group s-1-5-21-2068842505-1099708310-1153020420-1106@test.local
[Tue May 02 09:35:25.489404 2017] [autoindex:error] [pid 33379] [client 192.168.227.148:41672] AH01276: Cannot serve directory /var/www/html/: No matching DirectoryIndex (index.html) found, and server-generated directory index forbidden by Options directive
[Tue May 02 09:35:25.489460 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of Require valid-user : denied (no authenticated user yet)
[Tue May 02 09:35:25.489565 2017] [authz_core:debug] [pid 33379] mod_authz_core.c(809): [client 192.168.227.148:41672] AH01626: authorization result of <RequireAny>: denied (no authenticated user yet)
[Tue May 02 09:35:25.490392 2017] [auth_gssapi:error] [pid 33379] [client 192.168.227.148:41672] gss_accept_sec_context() failed: [Unspecified GSS failure.  Minor code may provide more information (Request is a replay)]
```
You should get similar output.

genadipost have successfully authenticated and the dbus call has returned his groups.

To finalize the Apache configuration we will configure the apache as a reverse proxy to rundeck, we will user RewriteEngine + RequestHeader to pass **X_REMOTE_USER** and **X_REMOTE_USER_GROUP** to rundeck.

Final Apache configuration:
```
LoadModule lookup_identity_module modules/mod_lookup_identity.so

<VirtualHost *:80>
   serverName rundeck.test.local

   ProxyPass / http://localhost:4440/
   ProxyPassReverse / http://localhost:4440/

   <Location />

    AuthType GSSAPI
    AuthName "Kerberos Login"
    GssapiCredStore keytab:/etc/httpd/http.keytab
    Require valid-user

    RewriteEngine On

    RewriteCond %{LA-U:REMOTE_USER} (.+)
    RewriteRule . - [E=RU:%1]
    RequestHeader set X-Remote-User "%{RU}e" env=RU

    LookupUserGroups REMOTE_USER_GROUP :

    RequestHeader set X-Remote-User-Group "%{REMOTE_USER_GROUP}e"

   </Location>
</VirtualHost>
```

Default SELinux policy prevents Apache to initiate outbound connections. Flip httpd_can_network_connect to 1:
```
setsebool -P httpd_can_network_connect 1
```

Restart Apache:
```
systemctl restart httpd
```

Rundeck:
=====

Install rundeck and its dependencies:
```
yum -y install java-1.8.0-headless  
yum -y install http://repo.rundeck.org/latest.rpm
yum -y install rundeck
```

Configure rundeck:

1. The file WEB-INF/web.xml (if CentOS /var/lib/rundeck/exp/webapp/WEB-INF/web.xml) inside the war contents must be modified to remove the `auth-constraint` element. 
```
<auth-constraint>
    <role-name>*</role-name>
</auth-constraint>
```
This disables the behavior which causes the Container to trigger its authentication mechanism when a user browses to a Rundeck page requiring authorizaton.

2. enable preauthenticated, add the following lines to /etc/rundeck/rundeck-config.properties:
```
# Pre Auth mode settings
rundeck.security.authorization.preauthenticated.enabled=true
rundeck.security.authorization.preauthenticated.attributeName=REMOTE_USER_GROUPS
rundeck.security.authorization.preauthenticated.delimiter=:

# Header from which to obtain user name
rundeck.security.authorization.preauthenticated.userNameHeader=X-Remote-User

# Header from which to obtain list of roles
rundeck.security.authorization.preauthenticated.userRolesHeader=X-Remote-User-Group

# Redirect to upstream logout url
rundeck.security.authorization.preauthenticated.redirectLogout=true
```

Start rundeck:
```
systemctl restart rundeckd
```

Access rundeck url (port 80) via browser with a domain user, if everything is configured well you should get the following message:
```
You have no authorized access to project
```

The user successfully authenticated and has been authorized, but he has no permissions.
To test the authorization we will copy the admin aclpolicy.
```
cp /etc/rundeck/admin.aclpolicy /etc/rundeck/s-1-5-21-2068842505-1099708310-1153020420-519.aclpolicy
chown rundeck:rundeck /etc/rundeck/s-1-5-21-2068842505-1099708310-1153020420-519.aclpolicy
```

```s-1-5-21-2068842505-1099708310-1153020420-519``` is the SID of one genadipost's user groups.

We will edit ```/etc/rundeck/s-1-5-21-2068842505-1099708310-1153020420-519.aclpolicy``` to apply the policy to Active Directory group:
```
description: Admin, all access.
context:
  project: '.*' # all projects
for:
  resource:
    - allow: '*' # allow read/create all kinds
  adhoc:
    - allow: '*' # allow read/running/killing adhoc jobs
  job:
    - allow: '*' # allow read/write/delete/run/kill of all jobs
  node:
    - allow: '*' # allow read/run for all nodes
by:
  group: s-1-5-21-2068842505-1099708310-1153020420-519@test.local

---

description: Admin, all access.
context:
  application: 'rundeck'
for:
  resource:
    - allow: '*' # allow create of projects
  project:
    - allow: '*' # allow view/admin of all projects
  project_acl:
    - allow: '*' # allow admin of all project-level ACL policies
  storage:
    - allow: '*' # allow read/create/update/delete for all /keys/* storage content
by:
  group: s-1-5-21-2068842505-1099708310-1153020420-519@test.local
``` 

No restart is needed, try to access the rundeck url again and you should get full permissions (of-course you should write acl policy for each group).


SOURCES:
========

- http://www.freeipa.org/page/Web_App_Authentication
- https://github.com/freeipa/freeipa-workshop#unit-5-web-application-authentication-and-authorisation
- https://www.adelton.com/apache/mod_lookup_identity/
- https://www.adelton.com/docs/idm/external-identities-os-and-web
- https://www.adelton.com/docs/idm/external-and-federated-identities
- https://serverfault.com/questions/570800/apache-mod-proxymod-rewrite-request-exceeded-the-limit-error
- https://serverfault.com/questions/207301/get-the-authenticated-user-under-apache
- https://www.safesquid.com/content-filtering/integrating-linux-host-windows-ad-kerberos-sso-authentication#h.wz9jygqxw6vc
- https://kollegaru.wordpress.com/2014/03/20/kerberos-authentication-ad-ds-from-linux
- http://rundeck.org/docs/administration/authenticating-users.html
- http://rundeck.org/docs/administration/access-control-policy.html
