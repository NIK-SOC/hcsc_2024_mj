LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := antiskid
LOCAL_SRC_FILES := antiskid_jni.c

include $(BUILD_SHARED_LIBRARY)
