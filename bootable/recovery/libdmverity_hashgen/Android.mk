# Copyright 2005 The Android Open Source Project
#
# Android.mk for adb
#
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := libdmverity_hashgen.c

LOCAL_CFLAGS := -Wall -DPARALLEL_HASH

LOCAL_C_INCLUDES += $(LOCAL_PATH)/..\
		$(TOP)/external/openssl/include
#LOCAL_C_INCLUDES += system/extras/ext4_utils


LOCAL_MODULE := libdmverity_hashgen
LOCAL_STATIC_LIBRARIES := libc libcrypto_static_dmverity

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := dm_verity_hash
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -D__NO_UI_PRINT
LOCAL_CFLAGS += -D__USE_DM_VERITY -g

LOCAL_SRC_FILES := dm_verity_hash.c 
LOCAL_C_INCLUDES += system/extras/ext4_utils \
	$(TOP)/external/openssl/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..

LOCAL_STATIC_LIBRARIES := \
	libc \
	libstdc++ \
	libext4_utils_static \
	libmtdutils \
	libdmverity_hashgen \
	libmincrypt \
	libcrypto_static_dmverity
	
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_SRC_FILES := libdmverity_hashgen.c

LOCAL_CFLAGS := -Wall

LOCAL_C_INCLUDES += $(LOCAL_PATH)/.. \
		$(TOP)/external/openssl/include
#LOCAL_C_INCLUDES += system/extras/ext4_utils

LOCAL_MODULE := libdmverity_hashgen_host

include $(BUILD_HOST_STATIC_LIBRARY)


# include $(CLEAR_VARS)

# LOCAL_SRC_FILES := libdmverity_hashgen.c img_dm_verity.c
# LOCAL_MODULE := img_dm_verity
# LOCAL_STATIC_LIBRARIES := libmincrypt libsparse_host libz

# include $(BUILD_HOST_EXECUTABLE)
