
https://yodleefinsoft.com/integration-documentation.html

https://developer.envestnet.com/resources/yodlee/data-model/docs/accounts

https://finvu.github.io/sandbox/
https://github.com/finvu
https://github.com/finvu/finvu-dh/tree/master/finvu-dh-ref

https://docs.setu.co/data/account-aggregator/overview


https://finvu.github.io/sandbox/fip_simulator/
This is a simulator implementation of the FIP API and can be used for testing 
the Account Aggregator flows as part of the ecosystem.


OMS AA
https://www.omsaa.com/sandbox/fip_data_api/index.html
https://www.omsaa.com/sandbox/index.html
aa_api_key - The HTTP header that needs to be set when a AA calls the FIP or FIU API. This header value is the token that FIP or FIU generates and gives to AA.

fip_api_key - This HTTP header needs to be set when FIP calls the AA APIs. This is a token that AA gives to FIP and is used in conjunction with the x-jws-signature header.

client_api_key - The HTTP header that needs to be set for every API call when FIU calls the AA APIs and value contains the token that AA gives to FIU. This is used in conjunction with the x-jws-signature that FIU will set in the API when calling AA.

x-jws-signature - HTTP header that contains the 'detached' signature of the body. API request/response need to be signed and the signature to be set in this header.



