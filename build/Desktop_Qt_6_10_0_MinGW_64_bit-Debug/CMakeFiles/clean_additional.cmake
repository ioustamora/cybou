# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\benchmark_crypto_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\benchmark_crypto_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\cybou_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\cybou_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\test_encryption_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\test_encryption_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\test_encryptionengine_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\test_encryptionengine_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\test_keymanager_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\test_keymanager_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\test_signatureengine_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\test_signatureengine_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\test_signatures_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\test_signatures_autogen.dir\\ParseCache.txt"
  "benchmark_crypto_autogen"
  "cybou_autogen"
  "test_encryption_autogen"
  "test_encryptionengine_autogen"
  "test_keymanager_autogen"
  "test_signatureengine_autogen"
  "test_signatures_autogen"
  )
endif()
