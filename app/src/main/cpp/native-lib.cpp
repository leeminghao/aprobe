#include <jni.h>

#include <stdint.h>
#include <stdlib.h>

#include <memory>
#include <string>

#include <aprobe/aprobe.h>

#include "debug.h"

void *my_malloc(size_t size)
{
  LOGD("my_malloc: %zu bytes memory are allocated.\n", size);
  return malloc(size);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_miot_aprobe_MainActivity_stringFromJNI(
    JNIEnv* env,
    jobject /* this */) {
  std::string hello = "Hello from C++";

  std::unique_ptr<aprobe::Aprobe> aprobe = aprobe::Aprobe::Create();
  aprobe->Register("", "malloc", (uint64_t)my_malloc);
  aprobe->Load();

  return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_miot_aprobe_MainActivity_test(JNIEnv *env, jobject thiz) {
  // TODO: implement test()
  char *test = (char*)malloc(10);
  LOGD("Malloc 10 bytes");
  return 0;
}
