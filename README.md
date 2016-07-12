Bob the certificate builder is a program to create self-signed certificates and to create a direct trust relationship between these certificates.

# The Name

The name bob the certificate builder is a joke about

- Bob the builder and
- Bob the guy who always gets secret message from Alice.

# Dependencies

To run bob you need to have 

- PyYAML
- OpenSSL
- KeyTool 

# Usage

```sh
bob config.yml 
```

With this line bob creates certificates and trust stores (e.g a CA file) for all services defined inside the configuration file.

Now the question is what is the content of the configuration file.

# Configuration

Here is an example of a configuration file

```yaml
bob:
    #The default algorithmn to be used by OpenSSL
    default_key_alg: "EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve"
    # A list of services
    services:
        - name: java_service # the alias name of this service
          # The certificate will have the following attributes when it has been created
          subject_str: "/C=DE/ST=NRW/L=Collogne/O=org/OU=oUnit/CN=service1.ou.org.de"
          # a list of confidants e.g. the public certificates this service has to connect to and needs to trust.
          confidants: [op, message_broker]
          # the certificates and trust store for this service needs to be available in the JKS format
          formats: JKS

        ## Broker
        - name: message_broker # the alias name of this message queue broker
          # The certificate will have the following attributes when it has been created
          subject_str: "/C=NL/ST=NH/L=Amsterdam/O=org/OU=oUnit/CN=broker.ou.org.nl"
          # a list of confidants e.g. the public certificates this service has to connect to and needs to trust.
          confidants: [service1, op]
          # the certificates and CAfile for this broker needs to be available in the PEM format
          formats: PEM
```

In this example we create two certificates, one for each service.
In addition we create a trust store (in Java speak) e.g. a list of trusted credentials which the service needs to trust.
With the newly created certificates the services would have the trust relation which you can see below.

```
     java_service---message_broker
```

But other constellations can be easily created.
Take a look at the following excerpt of a configuration

```yaml
    services:
        - name: java_service
          confidants: message_broker
        # ...

        - name: message_broker
          confidants: [java_service, node_service]
        # ...

        - name: node_service
          confidants: message_broker
        # ...
```

With this configuration you create certificates that allows both services to talk to the message broker, but not with each other. 

```
    java_service----message_broker----node_service
```

## Configuration format

The format of the configuration file is very simple

Here is a representation of the configuration format in something that resembles EBNF 

```
    bob:
        [default_key_alg: <string>]
        services:
            {
            - name: <string/scalar>
              subject_str: <string>
              confidants: (<sequence<string/scalar>> | <string/scalar>
              formats: (<sequence<scalar>> | <scalar>
             [key_alg: <string> ]
            }
```

The start of the bob configuration starts with the YAML association `bob:`.
This allows the configuration of bob to be merged with other tools like `rework` and `psst`.

It is possible to define a default key generation algorithm in our previous example we used
`"EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve"`.
This is the default value when you omit the `default_key_alg` line.
The format of this line comes from the [`openssl genpkey`][1] tool and you should *read the instructions carefully*when using this option.

Other possible option could be

- `RSA`
- `RSA -pkeyopt rsa_keygen_bits:2048`
- `EC -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve` 

After the default setup follows a list of service which starts with the association `services:`
Each service needs to have

- an alias name, which will be used in the confidants section
- a subject string, which represents the attributes for the certificates
- a list of strings or a single string which defines the which public certificates needs to available to this service
- a format or a list of formats in which the certificates needs to be. Possible options are 
    - `DER`
    - `JKS`
    - `PEM`
    - `PKCS12`
- an optional key algorithm, which should be used instead of the default value in `default_key_alg`.

# Security consideration

Bob was created to have a simpler mechanism to create *self singed certicates* compared to building them by hand with OpenSSL and KeyTool, or what will come in the future.

When you use these certificates you have to know how you have to setup your software to use the certificates correctly.
This includes that you make sure that your services don't trusts any other CA which your OS or library might include by default.

Bob was also created for services where you have full administrative rights to configure your service correctly and you have not public interface.
Take a look at this answer on [information security][2], which explains the risks of self singed certificates.

In addition bob was designed for a use case where you have a more or less static setup.
This means that your are not constantly create and remove service.
This also implies that you can't use it for end users.

To conclude use bob to create self signed certificates for your backend services, where you want to protect your connections with TLS.



[1]: https://wiki.openssl.org/index.php/Manual:Genpkey(1)
[2]: http://security.stackexchange.com/questions/8110/what-are-the-risks-of-self-signing-a-certificate-for-ssl/8112#8112
