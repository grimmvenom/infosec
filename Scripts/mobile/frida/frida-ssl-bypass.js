Java.perform(function () {

    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {

        // Skip all the logic and just return the chain again :P
        console.log("IM IN ANDROID");

        return untrustedChain;
    }


});

