/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_boomaa_opends_usb_IOKit */

#ifndef _Included_com_boomaa_opends_usb_IOKit
#define _Included_com_boomaa_opends_usb_IOKit
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_boomaa_opends_usb_IOKit
 * Method:    createIterator
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_boomaa_opends_usb_IOKit_createIterator
  (JNIEnv *, jobject);

/*
 * Class:     com_boomaa_opends_usb_IOKit
 * Method:    next
 * Signature: (J)Lcom/boomaa/opends/usb/IOKitDevice;
 */
JNIEXPORT jobject JNICALL Java_com_boomaa_opends_usb_IOKit_next
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_boomaa_opends_usb_IOKit
 * Method:    close
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_boomaa_opends_usb_IOKit_close
  (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif
