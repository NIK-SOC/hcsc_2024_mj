const targetClass = 'hu.honeylab.hcsc.thereott.UtilsJNI';
const targetMethod = 'genSignature';

Java.perform(function() {
    const utilsJNI = Java.use(targetClass);

    utilsJNI.genSignature.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(method, path, responseStatus, headers, body, timestamp) {

        const signature = this.genSignature(
            "POST",
            "/flag",
            "",
            "x-tott-app-id:hu.honeylab.hcsc.thereott,x-tott-app-name:thereott",
            "flag",
            timestamp
        );

        console.log('Generated signature and timestamp:', signature, timestamp);

        return signature;
    };
});
