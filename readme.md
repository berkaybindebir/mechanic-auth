## hapi-auth-man

Based on [**hapi-auth-cookie**](https://github.com/spumko/hapi-auth-cookie) added

* ACL support
* Inject credentials into view context

###Initialization

As you use ```hapi-auth-cookie```, you can register and use ```hapi-auth-man``` with same settings plus **roles**(check ACL part below) options.


```js
	 server.pack.register({
        plugin: require("hapi-auth-man"),
        options: {
            roles: {ROLES}
        }
    }, function (err) {

        if (err) {
            throw err;
        }
        
        server.auth.strategy("session", "cookie", {
            password: "secret_dont_forget_to_change_that",
            cookie: "sid",
            redirectTo: "/login",
            isSecure: false,
            validateFunc: function (session, callback) {
               
                // User is a Mongoose Model
                User.findById(session.sid, function (err, user) {
                    if (err || ! user) {
                        return callback("User not found");
                    }
                    var credentials = {
                        name: user.getFullName(),
                        mail: user.mail,
                        id: user._id
                    };
                    return callback(null, true, credentials);
                });
            }
        });
    });
    ...
   
```


###ACL Support

``roles`` must be object which keys specifies role names and correspondant function takes hapi **request** object and callback function which signature is ```callback(err, boolean)```


```javascript
{
	"superadmin": function (request, callback) {
            User.findById(request.auth.credentials.id, function (err, user) {
                if (err) {
                    callback(err);
                }
                else {
                    if (user.isSuperAdmin()) {
                        callback();
                    }
                    else {
                        callback("user is not superadmin");
                    }
                }
            });
        }
	"admin": function (request, callback) {
		
 	}
	...
}
```

Then, on your route handler you can spesify defined roles as plugin options,

```js
plugin.route({
        path: "/admin/superadmin",
        method: "GET",
        config: {
            auth: false,
            plugins: {
            		"hapi-auth-man": {
            			roles: ["superadmin", "admin"]
            		}
            }
            handler: {
                directory: {
                    path: Path.join(options.appPath, "/public"),
                    listing: false,
                    index: false
                }
            }
        }
    });
```

If user does not have the right permissions, ```hapi-auth-man``` reply with ```Boom.forbidden```;

```js
reply(Boom.forbidden(errorFromPolicyFunction);
``` 

###Inject credentials into view context

On hapi 's `onPreResponse` event, if response object contains successful authentication and response type is view,

`request.auth.credentials` injecting into the view context as a `credentials`

You can use it in templates files like;

```
// in handlebars
{{#if credentials}}
    <h2>{{credentials.id}}</h2>
{{/if}}

```



###Authentication

Check out [hapi-auth-cookie](https://github.com/spumko/hapi-auth-cookie)