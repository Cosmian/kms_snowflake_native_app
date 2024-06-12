CREATE_RSA_KEY_PAIR = """
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
"""