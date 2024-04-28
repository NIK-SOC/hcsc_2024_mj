#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

typedef char* (*BuildStringSecondPartFunc)(const char*, const char*, const char*, const char*, const char*, const char*);

const char * appName() {
    return "hu.honeylab.hcsc.thereott";
}

char *buildStringFirstPart(const char *method, const char *path, const char *responseStatus) {
    char *result = malloc(100);
    sprintf(result, "%s\n%s\n%s\n1.0\n%s\n", method, path, responseStatus, appName());
    return result;
}

char *rot47(const char *str) {
    char *result = malloc(strlen(str) + 1);
    char *p = result;
    while (*str) {
        if (*str >= 33 && *str <= 126) {
            *p = 33 + ((*str + 14) % 94);
        } else {
            *p = *str;
        }
        p++;
        str++;
    }
    *p = '\0';
    return result;
}

char *keyFirstPartReconstruct() {
    char *inputFirst = "zf$Idx@c8";
    char *inputSecond = "*)wcJ\"%%Gad";
    char *result = malloc(strlen(inputFirst) + strlen(inputSecond) + 1);
    strcpy(result, rot47(inputFirst));
    strcat(result, rot47(inputSecond));
    return result;
}

char *keySecondPartReconstruct() {
    char *inputFirst = "q";
    char *result = malloc(2);
    result[0] = inputFirst[0] - 33;
    result[1] = '\0';
    return result;
}

JNIEXPORT jstring JNICALL
Java_hu_honeylab_hcsc_thereott_UtilsJNI_genSignature(JNIEnv *env, jobject thiz, jstring method, jstring path, jstring responseStatus, jstring headers, jstring body, jstring timestamp) {
    const char *methodStr = (*env)->GetStringUTFChars(env, method, 0);
    const char *pathStr = (*env)->GetStringUTFChars(env, path, 0);
    const char *responseStatusStr = (*env)->GetStringUTFChars(env, responseStatus, 0);
    const char *headersStr = (*env)->GetStringUTFChars(env, headers, 0);
    const char *bodyStr = (*env)->GetStringUTFChars(env, body, 0);
    const char *timestampStr = (*env)->GetStringUTFChars(env, timestamp, 0);

    void *handle = dlopen("libutils.so", RTLD_LAZY);
    if (!handle) {
        return (*env)->NewStringUTF(env, "Error loading libutils.so");
    }

    char *firstPart = buildStringFirstPart(methodStr, pathStr, responseStatusStr);
    BuildStringSecondPartFunc buildStringSecondPart = dlsym(handle, "BuildStringSecondPart");
    char *result = buildStringSecondPart(keyFirstPartReconstruct(), keySecondPartReconstruct(), firstPart, headersStr, timestampStr, bodyStr);

    (*env)->ReleaseStringUTFChars(env, method, methodStr);
    (*env)->ReleaseStringUTFChars(env, path, pathStr);
    (*env)->ReleaseStringUTFChars(env, responseStatus, responseStatusStr);
    (*env)->ReleaseStringUTFChars(env, headers, headersStr);
    (*env)->ReleaseStringUTFChars(env, body, bodyStr);

    free(firstPart);
    dlclose(handle);

    return (*env)->NewStringUTF(env, result);
}
