LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
        dhcpclient.c \
        dhcpmsg.c \
        dhcp_utils.c \
        ifc_utils.c \
        packet.c
#-> PPPOE SUPPORT
ifeq (true,$(call spf_check,SEC_PRODUCT_FEATURE_WLAN_SUPPORT_PPPOE,TRUE))
LOCAL_SRC_FILES += pppoe_utils.c
endif
#<- PPPOE SUPPORT

LOCAL_SHARED_LIBRARIES := \
        libcutils \
        liblog

LOCAL_MODULE := libnetutils

LOCAL_CFLAGS := -Werror
LOCAL_CFLAGS += -DSAMSUNG_OXYGEN_NETWORK

include $(BUILD_SHARED_LIBRARY)
