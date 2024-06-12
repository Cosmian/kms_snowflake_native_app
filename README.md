> [![Built Status](https://api.cirrus-ci.com/github/%3CUSER%3E/kms_encrypt_python.svg?branch=main)](https://cirrus-ci.com/github/%3CUSER%3E/kms_encrypt_python)
>
> [![ReadTheDocs](https://readthedocs.org/projects/kms_encrypt_python/badge/?version=latest)](https://kms_encrypt_python.readthedocs.io/en/stable/)
>
> [![Coveralls](https://img.shields.io/coveralls/github/%3CUSER%3E/kms_encrypt_python/main.svg)](https://coveralls.io/r/%3CUSER%3E/kms_encrypt_python)
>
> [![PyPI-Server](https://img.shields.io/pypi/v/kms_encrypt_python.svg)](https://pypi.org/project/kms_encrypt_python/)
>
> [![Conda-Forge](https://img.shields.io/conda/vn/conda-forge/kms_encrypt_python.svg)](https://anaconda.org/conda-forge/kms_encrypt_python)
>
> [![Monthly Downloads](https://pepy.tech/badge/kms_encrypt_python/month)](https://pepy.tech/project/kms_encrypt_python)
>
> [![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&label=Twitter)](https://twitter.com/kms_encrypt_python)

[![Project generated with PyScaffold](https://img.shields.io/badge/-PyScaffold-005CA0?logo=pyscaffold)](https://pyscaffold.org/)

| 

# kms_encrypt_python

Example of using Python to perform encryption and decryption using the
Cosmian KMS

## Testing

Start a KMS Server

```shell
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.16.0
```

```shell
RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
ckms rsa keys create --size_in_bits 2048 --tag test_key
```

```json
{
  "kms_server_url": "https://cse.cosmian.com",
  "kms_access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjY3MTk2NzgzNTFhNWZhZWRjMmU3MDI3NGJiZWE2MmRhMmE4YzRhMTIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDQ3OTg0OTk0MjEwMDkwMzAzNzUiLCJoZCI6ImNvc21pYW4uY29tIiwiZW1haWwiOiJicnVuby5ncmllZGVyQGNvc21pYW4uY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJLUGJPZnZsXzV6cHJ5ZG4yUDE1NWpBIiwiaWF0IjoxNzE3MDY3Nzk2LCJleHAiOjE3MTcwNzEzOTZ9.ksctejTFDXHUS13ep7e4nlRxMZCo42kjV11bjHzRbMO0pud3pOGhCaNsRWP5ZW_1f7R8a007TKI6cN49sj-2UZCAGj0hF0ro8y6AQIeZimOZxeHv6rMNndjQoSqM7zUCjbk8gUgT8XRG4CGSyMMDQ6DqvnL_CJYmiXpnnEzgTsHLUy3wnHeApQtSedwF7laSI-70yPaX1ryf7kpzv3D-Zz3oW6lBZOa2AYJLolKPBobrMhA3B1W8Zw_RM1iaCMuqcaQq3oC6onj0yZj0KluwZ4bb1uFpkJGwwvDjfDGC5QfExcblFflK69_vvUExoL7Ft6rdVUfqhoeQr39waS0A3Q",
  "oauth2_conf": {
    "client_id": "996739510374-au9fdbgp72dacrsag267ckg32jf3d3e2.apps.googleusercontent.com",
    "client_secret": "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",
    "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_url": "https://oauth2.googleapis.com/token",
    "scopes": [
      "openid",
      "email"
    ]
  }
}
```

```json
{
  "tag": "CreateKeyPair",
  "type": "Structure",
  "value": [
    {
      "tag": "CommonAttributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "RSA"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 2048
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2097152
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentRSAPrivateKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "PrivateKey"
        },
        {
          "tag": "VendorAttributes",
          "type": "Structure",
          "value": [
            {
              "tag": "VendorAttributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "VendorIdentification",
                  "type": "TextString",
                  "value": "cosmian"
                },
                {
                  "tag": "AttributeName",
                  "type": "TextString",
                  "value": "tag"
                },
                {
                  "tag": "AttributeValue",
                  "type": "ByteString",
                  "value": "5B22746573745F6B6579225D"
                }
              ]
            }
          ]
        }
      ]
    },
    {
      "tag": "PrivateKeyAttributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "RSA"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 2048
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2097152
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentRSAPrivateKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "PrivateKey"
        }
      ]
    },
    {
      "tag": "PublicKeyAttributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "RSA"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 2048
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2097152
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentRSAPrivateKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "PrivateKey"
        }
      ]
    }
  ]
}
```


## Note {#pyscaffold-notes}

This project has been set up using PyScaffold 4.5. For details and usage
information on PyScaffold see <https://pyscaffold.org/>.
