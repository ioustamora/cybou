# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\cybou_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\cybou_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\test_encryption_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\test_encryption_autogen.dir\\ParseCache.txt"
  "CMakeFiles\\test_signatures_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\test_signatures_autogen.dir\\ParseCache.txt"
  "cybou_autogen"
  "test_encryption_autogen"
  "test_signatures_autogen"
  )
endif()
