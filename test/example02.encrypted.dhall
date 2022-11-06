let dhall-secret =
      https://raw.githubusercontent.com/jcouyang/dhall-secret/master/Type.dhall
        sha256:d7b55a2f433e19cf623d58c339346a604d96989f60cffdecee125a504a068dc9

in  { foo =
      { ageSecret =
          dhall-secret.AgeEncrypted
            { Recipients =
              [ "age1rl8j26etwulmav6yn8p4huu6944n7hsr2pyu2dr0evjzsj2tq92q48arjp"
              , "age1xmcwr5gpzkaxdwz2udww7lht2j4evp4vpl0ujeu64pe5ncpsk9zqhkfw5y"
              ]
            , CiphertextBlob =
                ''
                -----BEGIN AGE ENCRYPTED FILE-----
                YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBINUtOMnJzMFdyZXhnSUEr
                UGcyUlBuQ1pqdDRvTUtEYUVnS0FGR25HOWpJClFKVlNEeTBkZGJFUjAyNHJJMlRs
                M1VjN1FBclc4Qmh0M2kvRE9lV0JoZWcKLT4gWDI1NTE5IEc0ejJxclZFRmI2cWww
                Q0Ztc3VoK2FyYVNweXJWUURoWHVxN0ZNSHZ3UUEKUVUyT3NsRFN4MG4zaENITVNv
                OFhwaHk0cnRLK0RlaldYR25DYXpSZkVzcwotLS0gVlpPVGNHRnlZbU5mTWJHZ0Uz
                RmFTZmt0K0JZN3ZiNU0yRTNoVlpFOG03awrR//vOiCopVyEUXXrhiWDepXO4Ji8L
                E4nBuypVhk/xOWSTnNP0isKElAg=
                -----END AGE ENCRYPTED FILE-----
                ''
            }
      , plain = "hello world"
      }
    }